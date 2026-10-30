"""Root Linux control: host loopback exclusion, local exchange, actual parent wait."""
import ctypes
import errno
import os
import signal
import socket
import sys
import time


def main():
    from pathlib import Path
    sys.path.insert(0,str(Path(__file__).resolve().parent))
    from network_scope import isolated,configure
    from compartment import credentials
    if sys.platform!='linux' or os.getuid()!=0:
        raise RuntimeError('root Linux namespace control required')
    before=os.readlink('/proc/self/ns/net')
    with socket.socket() as ambient, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as ambient_udp:
        ambient.bind(('127.0.0.1',0))
        ambient.listen()
        ambient_port=ambient.getsockname()[1]
        ambient_udp.bind(('127.0.0.1',0))
        ambient_udp_port=ambient_udp.getsockname()[1]
        child=os.fork()
        if child==0:
            stage='close inherited host socket'
            try:
                ambient.close()
                ambient_udp.close()
                stage='unshare'
                if ctypes.CDLL(None,use_errno=True).unshare(0x40000000):
                    raise RuntimeError('private network control unshare')
                stage='configure isolated loopback'
                assert configure(before)==isolated(before)
                stage='drop credentials'
                credentials(20000)
                stage='exclude host service'
                with socket.socket() as probe:
                    probe.settimeout(1)
                    try:
                        probe.connect(('127.0.0.1',ambient_port))
                    except OSError as error:
                        assert error.errno in (errno.ECONNREFUSED,errno.ENETUNREACH)
                    else:
                        raise AssertionError('ambient host loopback reached')
                stage='exclude host datagram service'
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
                    probe.settimeout(1)
                    probe.connect(('127.0.0.1',ambient_udp_port))
                    probe.send(b'private')
                    try:
                        probe.recv(7)
                    except OSError as error:
                        assert error.errno==errno.ECONNREFUSED
                    else:
                        raise AssertionError('ambient host datagram reached')
                stage='local datagram exchange'
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as server, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                    server.settimeout(1)
                    server.bind(('127.0.0.1',0))
                    client.sendto(b'local',server.getsockname())
                    assert server.recvfrom(5)[0]==b'local'
                stage='local exchange'
                with socket.socket() as listener:
                    listener.bind(('127.0.0.1',0))
                    listener.listen()
                    with socket.socket() as client:
                        client.settimeout(1)
                        client.connect(listener.getsockname())
                        with listener.accept()[0] as server:
                            client.sendall(b'local')
                            assert server.recv(5)==b'local'
                os._exit(0)
            except BaseException as error:
                print('network control failure:',stage,type(error).__name__,getattr(error,'errno',None),flush=True)
                os._exit(1)
        deadline=time.monotonic()+10
        while True:
            waited,status=os.waitpid(child,os.WNOHANG)
            if waited==child:
                assert os.waitstatus_to_exitcode(status)==0
                print('isolated loopback exchange; host excluded; actual parent wait0')
                return
            if time.monotonic()>=deadline:
                os.kill(child,signal.SIGKILL)
                os.waitpid(child,0)
                raise TimeoutError('network scope control')
            time.sleep(0.01)


if __name__=='__main__':
    main()
