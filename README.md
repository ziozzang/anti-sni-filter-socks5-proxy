# anti-sni-filter-socks5-proxy
* Socks5 Proxy - bypass SNI/Host checking censorship.
* works with HTTP/HTTPS filtering at Korea.

# run

work and tested python2.

```
docker run --restart=always -d -v `pwd`:/opt --net=host python:2 python /opt/socks5proxy.py
```

# RFC
* https://tools.ietf.org/html/rfc1928
