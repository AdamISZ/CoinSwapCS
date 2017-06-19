from __future__ import print_function
from .configure import get_log
from twisted.internet import reactor

cslog = get_log()

class StateMachine(object):
    """A simple state machine that has integer states,
    incremented on successful execution of corresponding callbacks.
    See docs/state-machine.md for details and rationale.
    """
    def __init__(self, init_state, backout, callbackdata, default_timeout):
        self.num_states = len(callbackdata)
        self.init_state = init_state
        self.state = init_state
        #this is set to True to indicate that further processing
        #is not allowed (when backing out)
        self.freeze = False
        #this is set to True for the duration of execution of the
        #callback, as a lock to prevent multiple executions.
        self.state_in_process = False
        self.default_timeout = default_timeout
        #by default no pre- or post- processing
        self.setup = None
        self.finalize = None
        self.backout_callback = backout
        self.callbacks = []
        self.auto_continue = []
        self.timeouts = []
        for i,cbd in enumerate(callbackdata):
            self.callbacks.append(cbd[0])
            if cbd[1]:
                self.auto_continue.append(i)
            if cbd[2] > 0:
                self.timeouts.append(cbd[2])
            else:
                self.timeouts.append(self.default_timeout)

    def stallMonitor(self, state):
        """Wakes up a set timeout after state transition callback
        was called; if state has not been incremented, we backout.
        """
        if state < self.state or self.state == len(self.callbacks):
            return
        if not self.freeze:
            self.backout_callback('state transition timed out; backing out')
        self.freeze = True

    def tick(self, *args):
        """Executes processing for each state with order enforced.
        Runs pre- and post-processing step if provided.
        Optionally provide arguments - for callbacks receiving data from
        counterparty, these are provided, otherwise not.
        Calls backout_callback on failure, to allow
        the caller to execute backout conditional on state.
        """
        if self.state_in_process:
            cslog.info("Attempted to tick forward state but still in process, ignoring.")
            return (False, "Attempted to tick forward state but still in process, ignoring.")
        self.state_in_process = True
        if self.freeze:
            cslog.info("State machine is shut down, no longer receiving updates")
            return (False, "State machine is shut down, no longer receiving updates")
        if self.state == len(self.callbacks):
            cslog.info("State machine has completed.")
            return (False, "State machine has completed.")
        cslog.info("starting tick function, state is: " + str(self.state))     
        if self.setup:
            self.setup()
        if not args:
            retval, msg = self.execute_callback()
        else:
            retval, msg = self.execute_callback(*args)
        if not retval:
            cslog.info("Execution failed at step after: " + str(self.state) + \
                  ", backing out.")
            cslog.info("Error message: " + msg)
            #state machine must lock and prevent update from counterparty
            #at point of backout.
            self.freeze = True
            reactor.callLater(0, self.backout_callback, msg)
            return (False, msg)
        if self.finalize:
            if self.state > 2:
                self.finalize()
        cslog.info("State: " + str(self.state -1) + " finished OK.")
        #create a monitor call that's woken up after timeout; if we didn't
        #update, something is wrong, so backout
        if self.state < len(self.callbacks):
            reactor.callLater(self.timeouts[self.state],
                              self.stallMonitor, self.state)
        self.state_in_process = False
        if self.state in self.auto_continue:
            return self.tick()
        return (retval, msg)

    def execute_callback(self, *args):
        try:
            if args:
                retval, msg = self.callbacks[self.state](*args)
            else:
                retval, msg = self.callbacks[self.state]()
        except Exception as e:
            errormsg = "Failure to execute step after: " + str(self.state)
            errormsg += ", Exception: " + repr(e)
            cslog.info(errormsg)
            return (False, errormsg)
        if not retval:
            return (False, msg)
        #update to next state *only* on success.
        self.state += 1
        return (retval, "OK")

    def set_finalize(self, callback):
        self.finalize = callback

    def set_setup(self, callback):
        self.setup = callback
