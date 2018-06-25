#!/usr/bin/env python

from network import hello
import time
import thread


class Scheduler():
    def __init__(self):
        self.api_info = {"version": 3, "greeting": "hello"}
        self.suite = "niwa1-aa091"

    def about_api(self):
        return self.api_info

this_schd = Scheduler()

if __name__ == '__main__':
    flask_app = hello.create_app(this_schd)
    hello.start_app(flask_app)
    #thread.start_new_thread(hello.start_app(flask_app),())
    print('I got past the start!')
    time.sleep(40)
    hello.shutdown_server()
    print "Server on port %s stopped!" % hello.get_port()
    time.sleep(10)
    print("finished!")

