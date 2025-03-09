import threading
import time
import psutil
import logging
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether
from django.utils import timezone
from .models import PacketData, MonitoringSession

# Configure logging
logger = logging.getLogger(__name__)

class PacketCapture:
    """
    Handles network packet capture using Scapy and processes the captured packets
    """
    def __init__(self):
        self.is_running = False
        self.capture_thread = None
        self.stop_sniffing = threading.Event()
        self.current_session = None
        self.packet_count = 0
        self.whitelisted_apps = set()
        self.whitelisted_ips = set()
        self.process_cache = {}
        
    def _identify_application(self, src_port, dst_port, src_ip, dst_ip):
        """Identify which application is responsible for the network traffic"""
        try:
            for conn in psutil.net_connections(kind='inet'):
                if (conn.laddr.port == src_port or conn.laddr.port == dst_port or 
                    conn.raddr.port == src_port or conn.raddr.port == dst_port):
                    if conn.pid:
                        if conn.pid in self.process_cache:
                            return self.process_cache[conn.pid]
                        try:
                            proc = psutil.Process(conn.pid)
                            app_name = proc.name()
                            self.process_cache[conn.pid] = app_name
                            return app_name
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
        except (psutil.AccessDenied, PermissionError):
            logger.warning("Permission denied when accessing network connections")
        return "Unknown"
        
    def _packet_callback(self, packet):
        """Process each captured packet"""
        if self.stop_sniffing.is_set():
            return True  # Stop sniffing
        
        try:
            # Increment packet counter
            self.packet_count += 1
            
            # Initialize packet info
            packet_info = {
                'source_ip': None,
                'destination_ip': None,
                'protocol': None,
                'packet_size': len(packet),
                'source_port': None,
                'destination_port': None,
                'application': None,
                'packet_summary': str(packet.summary())
            }
            
            # Extract IP information
            if IP in packet:
                packet_info['source_ip'] = packet[IP].src
                packet_info['destination_ip'] = packet[IP].dst
                
                # Check if IP is whitelisted
                if (packet_info['source_ip'] in self.whitelisted_ips or 
                    packet_info['destination_ip'] in self.whitelisted_ips):
                    return
                
                # Extract protocol information
                if TCP in packet:
                    packet_info['protocol'] = 'TCP'
                    packet_info['source_port'] = packet[TCP].sport
                    packet_info['destination_port'] = packet[TCP].dport
                elif UDP in packet:
                    packet_info['protocol'] = 'UDP'
                    packet_info['source_port'] = packet[UDP].sport
                    packet_info['destination_port'] = packet[UDP].dport
                elif ICMP in packet:
                    packet_info['protocol'] = 'ICMP'
            elif ARP in packet:
                packet_info['protocol'] = 'ARP'
                packet_info['source_ip'] = packet[ARP].psrc
                packet_info['destination_ip'] = packet[ARP].pdst
            elif Ether in packet:
                packet_info['protocol'] = 'Ethernet'
            
            # Identify application
            if packet_info['source_port'] or packet_info['destination_port']:
                app_name = self._identify_application(
                    packet_info['source_port'], 
                    packet_info['destination_port'],
                    packet_info['source_ip'],
                    packet_info['destination_ip']
                )
                packet_info['application'] = app_name
                
                # Skip whitelisted applications
                if app_name in self.whitelisted_apps:
                    return
            
            # Store packet in database
            if self.current_session and self.current_session.is_active:
                PacketData.objects.create(**packet_info)
                
                # Update session packet count
                if self.packet_count % 100 == 0:  # Update every 100 packets to reduce DB operations
                    self.current_session.packets_captured = self.packet_count
                    self.current_session.save(update_fields=['packets_captured'])
                    
        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")
    
    def start_capture(self, interface=None, filter_str=None):
        """Start capturing packets"""
        if self.is_running:
            logger.warning("Packet capture is already running")
            return False
        
        try:
            # Create a new monitoring session
            self.current_session = MonitoringSession.objects.create(
                start_time=timezone.now(),
                is_active=True,
                session_description=f"Capture started on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
            
            # Reset packet counter
            self.packet_count = 0
            
            # Reset stop event
            self.stop_sniffing.clear()
            
            # Start capture in a separate thread
            self.is_running = True
            self.capture_thread = threading.Thread(
                target=self._run_capture, 
                args=(interface, filter_str),
                daemon=True
            )
            self.capture_thread.start()
            
            logger.info(f"Packet capture started on session {self.current_session.id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start packet capture: {str(e)}")
            self.is_running = False
            return False
    
    def _run_capture(self, interface, filter_str):
        """Run the Scapy sniffer in a separate thread"""
        try:
            sniff(
                iface=interface,
                filter=filter_str,
                prn=self._packet_callback,
                stop_filter=lambda _: self.stop_sniffing.is_set(),
                store=0  # Don't store packets in memory
            )
        except Exception as e:
            logger.error(f"Sniffing error: {str(e)}")
        finally:
            self.is_running = False
            
            # Update the session if it exists
            if self.current_session:
                self.current_session.is_active = False
                self.current_session.end_time = timezone.now()
                self.current_session.packets_captured = self.packet_count
                self.current_session.save()
    
    def stop_capture(self):
        """Stop the packet capture"""
        if not self.is_running:
            logger.warning("Packet capture is not running")
            return False
        
        self.stop_sniffing.set()
        
        # Wait for the thread to finish
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2.0)
        
        self.is_running = False
        logger.info("Packet capture stopped")
        return True
    
    def set_whitelisted_apps(self, apps):
        """Set the list of whitelisted applications"""
        self.whitelisted_apps = set(apps)
        
    def set_whitelisted_ips(self, ips):
        """Set the list of whitelisted IP addresses"""
        self.whitelisted_ips = set(ips)
        
    def get_capture_status(self):
        """Get the current status of packet capture"""
        return {
            'is_running': self.is_running,
            'packet_count': self.packet_count,
            'session_id': self.current_session.id if self.current_session else None,
            'start_time': self.current_session.start_time if self.current_session else None,
            'duration': self.current_session.duration() if self.current_session else None
        }


# Create a singleton instance
packet_capture = PacketCapture() 