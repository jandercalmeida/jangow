#!/usr/bin/python3

from twisted.internet import reactor
from twisted.web import resource, server

class MyResource(resource.Resource):
    isLeaf = True
    def render_GET(self, request):
        return 'gotten'

site = server.Site(MyResource())

reactor.listenTCP(23, site)
reactor.listenTCP(25, site)
reactor.listenTCP(53, site)
reactor.listenTCP(80, site)
reactor.listenTCP(110, site)
reactor.listenTCP(138, site)
reactor.listenTCP(139, site)
reactor.listenTCP(161, site)
reactor.listenTCP(389, site)
reactor.listenTCP(443, site)
reactor.listenTCP(445, site)
reactor.listenTCP(3128, site)

reactor.run()
