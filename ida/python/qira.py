# import wingdbstub
# wingdbstub.Ensure()
import time
from threading import Thread
from SimpleWebSocketServer import SimpleWebSocketServer, WebSocket

import idaapi
import idc


CLIENTS = []
DEBUG = False

class qiraplugin_t(idaapi.plugin_t):
    flags = 0
    comment = "QEMU Interactive Runtime Analyser plugin"
    help = "Visit qira.me for more infos"
    wanted_name = "QIRA Plugin"
    wanted_hotkey = "Alt-F5"

    def __init__(self):
        self.max_comment_len = 100
        self.qira_address = idc.BADADDR
        self.wsserver = None
        self.old_addr = None
        self.port = 3003
        self.addr = None
        self.cmd = None

    def init(self):
        ret = self.start()
        idaapi.msg("[%s] Initialized: Ready to go!\n" % (self.comment,))

        return ret

    def start(self):
        # if __name__ == '__main__':
        server = Thread(target=self.ws_server, args=(3003,))
        try:
            server.start()
            return idaapi.PLUGIN_KEEP
        except AttributeError:
            return idaapi.PLUGIN_SKIP

    def ws_server(self, port):
        if port is None:
            port = self.port
        host = ''
        self.wsserver = SimpleWebSocketServer(host, port, QiraServer, selectInterval=0.1)
        if self.wsserver is not None:
            idaapi.msg("[%s] Starting WS Server\n" % (self.comment,))
            self.wsserver.serveforever()
        else:
            idaapi.msg("[%s] Cannot Start WS Server\n" % (self.comment,))

    def ws_send(self, msg):
        if self.wsserver is not None:
            self.start()
        if msg is not None:
            if msg == 'connected':
                for conn in list(CLIENTS):
                    conn.sendMessage(msg)
                    time.sleep(1)
                CLIENTS.append(self)
            elif msg == 'closed':
                CLIENTS.remove(self)
                for conn in list(CLIENTS):
                    conn.sendMessage(msg)
                    time.sleep(1)
            else:
                # print "Tuple: %s" % (self.wsserver.connections.items(),)
                # This one still have errors in both items()/CLIENTS
                for conn in list(self.wsserver.connections.items()):
                    if conn != self:
                        # debugging
                        if DEBUG:
                            idaapi.msg("[%s] ws_send : %s\n" % (self.wanted_name, msg,))
                        conn.sendMessage(msg)
                    time.sleep(0.1)
        else:
            idaapi.msg("[%s] ws_send : Cannot send null\n" % (self.comment,))

    def set_qira_address(self, sea):
        # Check if there is a BreakPoint and delete is before processing.
        if (self.qira_address is not None) and (
                self.qira_address != idc.BADADDR):
            qea = idaapi.toEA(0, self.qira_address)
            if idc.CheckBpt(qea) != -1:
                idaapi.del_bpt(qea)
        # Update qira_address and set BreakPont.
        self.qira_address = sea
        idaapi.add_bpt(self.qira_address, 0, idaapi.BPT_SOFT)
        idc.EnableBpt(self.qira_address, False)
        # debugging
        if DEBUG:
            idaapi.msg(
                "[%s] set_qira_address: 0x%x\n" %
                (self.wanted_name, self.qira_address,))

    def send_names(self):
        qira_names = idaapi.get_nlist_size()
        for i in range(0, qira_names):
            self.cmd = "setname 0x%x %s" % (
                idaapi.get_nlist_ea(i), idaapi.get_nlist_name(i))
            # debugging
            if DEBUG:
                idaapi.msg(
                    "[%s] send_names: EA [0x%x], Name [%s]\n" %
                    (self.wanted_name, idaapi.get_nlist_ea(i),
                     idaapi.get_nlist_name(i),))
            self.ws_send(self.cmd)

    def send_comments(self):
        start = idaapi.get_segm_base(idaapi.get_first_seg())
        cur = start
        while True:
            if cur != idc.BADADDR:
                cmt = idaapi.get_cmt(cur, 0)
                if (cmt is not None) and (cmt != idc.BADADDR):
                    self.cmd = "setcmt 0x%x %s" % (cur, cmt)
                    # debugging
                    if DEBUG:
                        idaapi.msg(
                            "[%s] send_comments: EA [0x%x], Comment [%s]\n" %
                            (self.wanted_name, cur, cmt,))
                    self.ws_send(self.cmd)
            else:
                break
            cur = idc.NextAddr(cur)

        return True

    def update_address(self, addr_type, addr):
        if (addr_type is not None) and (addr is not None):
            self.cmd = "set%s 0x%x" % (addr_type, addr)
            self.ws_send(self.cmd)
        else:
            idaapi.msg(
                "[%s] Cannot update address: 'None'\n" %
                (self.wanted_name,))

    def jump_to(self, qea):
        if qea is not None:
            if (qea != self.qira_address) and (qea != idc.BADADDR):
                self.set_qira_address(qea)
                idaapi.jumpto(self.qira_address, -1, 0x0001)
            else:
                idaapi.jumpto(self.qira_address, -1, 0x0001)
            # debugging
            if DEBUG:
                idaapi.msg(
                    "[%s] jump_to: qira_address [0x%x], ea [0x%x]\n" %
                    (self.wanted_name, self.qira_address, qea,))
        else:
            idaapi.msg("[%s] Cannot jump_to: None\n")

    def run(self, arg):
        idaapi.msg("[%s] Syncing with WS Server\n" % (self.wanted_name,))
        self.addr = idaapi.get_screen_ea()
        if self.old_addr != self.addr:
            # check against idc.BADADDR and None before going
            if (self.addr is not None) and (self.addr != idc.BADADDR):
                # Code Address
                if idaapi.isCode(idaapi.getFlags(self.addr)):
                    # don't set the address if it's already the qira_address
                    if self.addr != self.qira_address:
                        # debugging
                        if DEBUG:
                            idaapi.msg(
                                "[%s] Qira Address 0x%x \n" %
                                (self.wanted_name, self.addr,))
                        # Instruction Address
                        self.set_qira_address(self.addr)
                        self.update_address("iaddr", self.addr)
                # Data Address
                elif idaapi.isData(idaapi.getFlags(self.addr)):
                    self.update_address("daddr", self.addr)
                # Tail Address
                elif idaapi.isTail(idaapi.getFlags(self.addr)):
                    self.update_address("taddr", self.addr)
                # Unknown Address
                elif idaapi.isUnknown(idaapi.getFlags(self.addr)):
                    self.update_address("uaddr", self.addr)
                # Head Address
                elif idaapi.isHead(idaapi.getFlags(self.addr)):
                    self.update_address("haddr", self.addr)
                # Flow Address
                elif idaapi.isFlow(idaapi.getFlags(self.addr)):
                    self.update_address("faddr", self.addr)
                # Var Address
                elif idaapi.isVar(idaapi.getFlags(self.addr)):
                    self.update_address("vaddr", self.addr)
                # Data Address
                else:
                    self.update_address("daddr", self.addr)

        self.old_addr = self.addr

    def stop(self):
        if self.wsserver is not None:
            self.wsserver.close()
            self.wsserver = None
        else:
            idaapi.msg("[%s] is not running.\n" % (self.wanted_name,))

    def term(self):
        idaapi.msg("[%s] Terminating tasks...\n" % (self.wanted_name,))
        try:
            self.stop()
        except AttributeError:
            pass
        idaapi.msg("[%s] Uninstalled!\n" % (self.wanted_name,))


def PLUGIN_ENTRY():
    return qiraplugin_t()


###################
#                 #
#    QIRA CODE    #
#                 #
###################


class QiraServer(WebSocket):

    def __init__(self, server, sock, address):
        WebSocket.__init__(self, server, sock, address)
        self.qira = qiraplugin_t()
        idaapi.msg("[%s] Starting QIRA web...\n" % (self.qira.comment,))

    def init(self):
        self.qira.send_names()
        self.qira.send_comments()

    def qsjump_to(self, qs_ea):
        try:
            self.qira.jump_to(qs_ea)
        except AttributeError:
            idaapi.msg(
                "[%s] qsjump_to : Addr is not valid (%s)\n" %
                (self.qira.wanted_name, qs_ea,))

    def qs_send_msg(self, qs_msg):
        try:
            self.qira.ws_send(qs_msg)
        except AttributeError:
            idaapi.msg(
                "[%s] qs_send_msg : Cannot send message (%s)\n" %
                (self.qira.wanted_name, qs_msg,))

    def handleMessage(self):
        # debugging
        if DEBUG:
            idaapi.msg(
                "[%s] Received from QIRA web: %s\n" %
                (self.qira.wanted_name, self.data,))
        dat = self.data.split(" ")
        if (dat[0] == "setaddress") and (dat[1] != "undefined"):
            try:
                qs_ea = idaapi.toEA(0, int(str(dat[1][2:]), 16))
                # debugging
                if DEBUG:
                    idaapi.msg(
                        "[%s] EA address 0x%x\n" %
                        (self.qira.wanted_name, qs_ea,))
                self.qsjump_to(qs_ea)
            except AttributeError:
                idaapi.msg(
                    "[%s] Error processing the address\n" %
                    (self.qira.wanted_name,))

    def handleConnected(self):
        self.qs_send_msg('connected')
        idaapi.msg("[%s] Client connected\n" % (self.qira.wanted_name,))

    def handleClose(self):
        self.qs_send_msg('closed')
        idaapi.msg("[%s] WebSocket closed\n" % (self.qira.wanted_name,))
