from angr import SimProcedure
import claripy


class IsDebugPresentHook(SimProcedure):
    def run(self):
        print('IsDebugPresentHook running')
        return 0


class SetAppTypeHook(SimProcedure):
    def run(self, app_type):
        print(self.state.se.eval(app_type,int))
        self.ret()

class IsDebuggerPresentHook(SimProcedure):
    def run(self):
        print('IsDebuggerPresent')
        return 0

class inetAdressHook(SimProcedure):
    def run(self, ip):
        print('inetAdress')
        print(self.state.se.eval(ip, cast_to="string"))
        #Debería retornar un valor
        self.ret()


class SimpleHook(SimProcedure):
    def run(self):
        self.ret()
