from __future__ import print_function
from coinswap import StateMachine
import time


class BadStateMachine(StateMachine):
    """The default state machine doctored to trigger reload/recover
    on a specific state being reached.
    """
    def __init__(self, init_state, backout, callbackdata, fail_info):
        super(BadStateMachine, self).__init__(init_state, backout, callbackdata,
                                              20.0)
        self.fail_state, self.fail_callback = fail_info

    def tick(self, *args):
        if self.state == self.fail_state:
            self.freeze = True
            self.fail_callback()
        else:
            return super(BadStateMachine, self).tick(*args)
