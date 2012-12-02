import logging
import urlparse
import re
from socket import MSG_PEEK

import dns.resolver
import gevent
import gevent.pool
import gevent.server
import gevent.socket

def peek_http_host(socket):
    hostname = ''
    hostheader = re.compile('host: ([^\(\);:,<>]+)', re.I)
    # Peek up to 512 bytes into data for the Host header
    for n in [128, 256, 512]:
        bytes = socket.recv(n, MSG_PEEK)
        if not bytes:
            break
        for line in bytes.split('\r\n'):
            match = hostheader.match(line)
            if match:
                hostname = match.group(1)
        if hostname:
            break
    return hostname

def recv_http_headers(socket):
    pass

def lookup_txt_attribute(domain, attribute, prefix=None, resolve_wildcard=True):
    if prefix:
        domain = '.'.join([prefix, domain])
    attribute = attribute.lower()
    try:
        answers = dns.resolver.query(domain, 'TXT')
        for answer in answers:
            for data in answer.strings:
                if data.lower().startswith('{0}='.format(attribute)):
                    return data.split('=', 1)[1]
        if resolve_wildcard:
            root = lookup_txt_attribute(domain, 'root',
                        resolve_wildcard=False)
            if root:
                return lookup_txt_attribute(root, attribute,
                            resolve_wildcard=False)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass

def join_sockets(a, b):
    def _pipe(from_, to):
        while True:
            try:
                data = from_.recv(64 * 1024)
                if not data:
                    break
                try:
                    to.sendall(data)
                except:
                    from_.close()
                    break
            except:
                break
        try:
            to.close()
        except: 
            pass
    class _codependents(gevent.pool.Group):
        def discard(self, greenlet):
            super(_codependents, self).discard(greenlet)
            if not hasattr(self, '_killing'):
                self._killing = True
                gevent.spawn(self.kill)
    return _codependents([
        gevent.spawn(_pipe, a, b),
        gevent.spawn(_pipe, b, a),
    ])

def handler(socket, address):
    hostname = peek_http_host(socket)
    hostname = hostname.split(':')[0]
    if not hostname:
        logging.debug("!no hostname, closing")
        socket.close()
        return

    redirect_url = lookup_txt_attribute(hostname, 'location', '_redirect')
    if redirect_url:
        # only append path in request if redirect location 
        # is completely pathless. ex: http://example.com
        # however, we don't pass query params...
        if redirect_url.count('/') == 2:
            req_tip = socket.recv(256)
            method, path, _ = req_tip.split(' ', 2)
            redirect_url = '{0}{1}'.format(redirect_url, 
                                urlparse.urlparse(path).path)
        resp = """
HTTP/1.1 301 Moved Permanently\r\nLocation: {0}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n
""".format(redirect_url).strip()
        socket.sendall(resp)
        socket.close()
        return

    proxy_to = lookup_txt_attribute(hostname, 'address', '_proxy')
    if proxy_to:
        address = proxy_to.split(':')
        if len(address) == 1:
            address = (address[0], 80)
        backend = gevent.socket.create_connection(address)
        # TODO: insert headers: Via, X-Forwarded-For, Host
        join_sockets(socket, backend)

def run():
    logging.basicConfig(
        format="%(asctime)s %(levelname) 7s %(module)s: %(message)s",
        level=logging.DEBUG)
    
    server = gevent.server.StreamServer(('0.0.0.0', 8000), handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    run()
