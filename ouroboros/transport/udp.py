"""
UDP Transport for Ouroboros Protocol.

Provides UDP network transport with async and sync interfaces.
"""

import socket
import asyncio
from typing import Optional, Tuple, Callable
from ..protocol.packet import OuroborosPacket


class TransportError(Exception):
    """Raised when transport operations fail."""
    pass


class UDPTransport:
    """
    UDP transport implementation for Ouroboros.
    
    Provides both synchronous and asynchronous UDP communication.
    """
    
    def __init__(self, local_host: str = "0.0.0.0", local_port: int = 0):
        """
        Initialize UDP transport.
        
        Args:
            local_host: Local interface to bind to
            local_port: Local port to bind to (0 = auto-assign)
        """
        self.local_host = local_host
        self.local_port = local_port
        self._socket: Optional[socket.socket] = None
        self._is_bound = False
    
    def bind(self) -> None:
        """
        Bind the UDP socket to local address.
        
        Raises:
            TransportError: If binding fails
        """
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.bind((self.local_host, self.local_port))
            
            # Update local_port if auto-assigned
            if self.local_port == 0:
                self.local_port = self._socket.getsockname()[1]
            
            self._is_bound = True
            
        except Exception as e:
            raise TransportError(f"Failed to bind UDP socket: {e}")
    
    def send_packet(self, packet: OuroborosPacket, remote_host: str, remote_port: int) -> None:
        """
        Send a packet to a remote address.
        
        Args:
            packet: Packet to send
            remote_host: Destination IP address
            remote_port: Destination port
            
        Raises:
            TransportError: If sending fails
        """
        if not self._is_bound:
            self.bind()
        
        try:
            packet_bytes = packet.to_bytes()
            self._socket.sendto(packet_bytes, (remote_host, remote_port))
            
        except Exception as e:
            raise TransportError(f"Failed to send packet: {e}")
    
    def receive_packet(self, timeout: float = None) -> Tuple[OuroborosPacket, Tuple[str, int]]:
        """
        Receive a packet from the network.
        
        Args:
            timeout: Receive timeout in seconds (None = blocking)
            
        Returns:
            Tuple of (packet, (sender_host, sender_port))
            
        Raises:
            TransportError: If receiving fails
            TimeoutError: If timeout expires
        """
        if not self._is_bound:
            self.bind()
        
        try:
            if timeout is not None:
                self._socket.settimeout(timeout)
            
            data, addr = self._socket.recvfrom(4096)  # Max packet size
            packet = OuroborosPacket.from_bytes(data)
            
            return packet, addr
            
        except socket.timeout:
            raise TimeoutError("Receive timeout expired")
        except Exception as e:
            raise TransportError(f"Failed to receive packet: {e}")
    
    def close(self) -> None:
        """Close the UDP socket."""
        if self._socket:
            self._socket.close()
            self._socket = None
            self._is_bound = False
    
    def get_local_address(self) -> Tuple[str, int]:
        """
        Get the local bound address.
        
        Returns:
            Tuple of (host, port)
        """
        if not self._is_bound:
            raise TransportError("Socket not bound")
        
        return self._socket.getsockname()
    
    def __repr__(self):
        status = "bound" if self._is_bound else "unbound"
        return f"UDPTransport({self.local_host}:{self.local_port}, {status})"
    
    def __enter__(self):
        """Context manager entry."""
        self.bind()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


class AsyncUDPTransport:
    """
    Asynchronous UDP transport for high-performance applications.
    """
    
    def __init__(self, local_host: str = "0.0.0.0", local_port: int = 0):
        """
        Initialize async UDP transport.
        
        Args:
            local_host: Local interface to bind to
            local_port: Local port to bind to (0 = auto-assign)
        """
        self.local_host = local_host
        self.local_port = local_port
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._protocol: Optional['_AsyncUDPProtocol'] = None
        self._is_bound = False
    
    async def bind(self) -> None:
        """
        Bind the async UDP socket.
        
        Raises:
            TransportError: If binding fails
        """
        try:
            loop = asyncio.get_event_loop()
            
            self._transport, self._protocol = await loop.create_datagram_endpoint(
                lambda: _AsyncUDPProtocol(),
                local_addr=(self.local_host, self.local_port)
            )
            
            # Update local_port if auto-assigned
            if self.local_port == 0:
                self.local_port = self._transport.get_extra_info('sockname')[1]
            
            self._is_bound = True
            
        except Exception as e:
            raise TransportError(f"Failed to bind async UDP socket: {e}")
    
    async def send_packet(self, packet: OuroborosPacket, remote_host: str, remote_port: int) -> None:
        """
        Send a packet asynchronously.
        
        Args:
            packet: Packet to send
            remote_host: Destination IP address
            remote_port: Destination port
            
        Raises:
            TransportError: If sending fails
        """
        if not self._is_bound:
            await self.bind()
        
        try:
            packet_bytes = packet.to_bytes()
            self._transport.sendto(packet_bytes, (remote_host, remote_port))
            
        except Exception as e:
            raise TransportError(f"Failed to send packet: {e}")
    
    async def receive_packet(self, timeout: float = None) -> Tuple[OuroborosPacket, Tuple[str, int]]:
        """
        Receive a packet asynchronously.
        
        Args:
            timeout: Receive timeout in seconds (None = no timeout)
            
        Returns:
            Tuple of (packet, (sender_host, sender_port))
            
        Raises:
            TransportError: If receiving fails
            TimeoutError: If timeout expires
        """
        if not self._is_bound:
            await self.bind()
        
        try:
            if timeout:
                data, addr = await asyncio.wait_for(
                    self._protocol.receive_packet(), timeout=timeout
                )
            else:
                data, addr = await self._protocol.receive_packet()
            
            packet = OuroborosPacket.from_bytes(data)
            return packet, addr
            
        except asyncio.TimeoutError:
            raise TimeoutError("Receive timeout expired")
        except Exception as e:
            raise TransportError(f"Failed to receive packet: {e}")
    
    def close(self) -> None:
        """Close the async UDP transport."""
        if self._transport:
            self._transport.close()
            self._transport = None
            self._protocol = None
            self._is_bound = False
    
    def get_local_address(self) -> Tuple[str, int]:
        """
        Get the local bound address.
        
        Returns:
            Tuple of (host, port)
        """
        if not self._is_bound:
            raise TransportError("Transport not bound")
        
        return self._transport.get_extra_info('sockname')


class _AsyncUDPProtocol(asyncio.DatagramProtocol):
    """Internal protocol handler for async UDP transport."""
    
    def __init__(self):
        self._receive_queue = asyncio.Queue()
    
    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Handle received datagram."""
        self._receive_queue.put_nowait((data, addr))
    
    async def receive_packet(self) -> Tuple[bytes, Tuple[str, int]]:
        """Receive a packet from the queue."""
        return await self._receive_queue.get()
