# coding:utf-8
import socket
import uuid
import struct
import sys
import time


class AC_client():
    def __init__(self, loc_ip, loc_port, dst_ip, dst_port):
        self.loc_ip = loc_ip
        self.dst_ip = dst_ip
        self.loc_port = loc_port
        self.dst_port = dst_port
        self.times = 0
        self.mac_address = b'\xff\xff\xff\xff\xff\xff'
        # self.mac_address = b'\x00\x00\x00\x00\x00\x00'

    # 获取本地IP地址
    def get_ip_address(self):
        local_ip = socket.gethostbyname(socket.gethostname()).split('.')
        local_ip = [int(local_ip[i]) for i in range(len(local_ip))]
        return local_ip

        # 获取本地mac地址,注意，若本机的有虚拟机网卡，或者网卡多于一个则不能使用该方法
        # def get_mac_address(self):
        #     mac_address = uuid.UUID(int = uuid.getnode()).hex[-12:]
        #     mac_address = [int(mac_address[e:e+2],16) for e in range(0,11,2)]

        #     return mac_address

        # # 角色报文
        # def role_message(self, echo_req_buffer):
        #     local_mac_address = self.get_mac_address()
        #     req_mac_address = struct.unpack('24B',echo_req_buffer)[8:14]
        #     for x, y in zip(local_mac_address,req_mac_address):
        #         if x < y:
        #             role = b'\x01'
        #             return role
        #         elif  x > y:
        #             role = b'\x02'
        #             return role
        #     role = b'\x00'

        # return role

    # 请求次数
    def req_times(self):
        times = struct.pack('B', self.times)

        return times

    # 探测请求
    def echo_req(self):
        head = b'\x15\x81'
        version = b'\x00\x02'
        type_ = b'\x00\x00'
        length = b'\x00\x0e'
        mac_address = self.mac_address

        t = b'\x04'
        l = b'\x08'
        layer = b'\x00\x00\x00\x02'
        backup_type = b'\x00\x00\x00\x01'
        echo_req_buffer = head + version + type_ + length + mac_address + \
                          t + l + layer + backup_type

        return echo_req_buffer

    # 探测回复
    def echo_ack(self, echo_req_buffer):
        head = b'\x15\x81'
        version = b'\x00\x02'
        type_ = b'\x00\x01'
        length = b'\x00\x68'
        role = b'\x02'
        ip_type = b'\x00'
        loc_ip = self.loc_ip.split('.')
        ip = [int(loc_ip[i]) for i in range(len(loc_ip))]
        local_ip = struct.pack('4B', ip[0], ip[1], ip[2], ip[3])
        mac_address = self.mac_address
        software_version = b'\x31\x2e\x30\x2e\x30\x2e\x39\x65\x39\x63' + \
                           b'\x38\x31\x63\x63\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + \
                           b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + \
                           b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + \
                           b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        times = self.req_times()
        last_num = struct.pack('3B', 0X00, 0X00, 0X00) + times
        ipv6 = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        echo_ack_message = head + version + type_ + length + role + ip_type + local_ip + \
                           mac_address + software_version + last_num + ipv6

        return echo_ack_message

    # 握手回复
    def hdsk_ans(self, hdsk_req_buffer):
        head = b'\x15\x81'
        version = b'\x00\x02'
        type_ = b'\x00\x03'
        length = b'\x00\x18'
        result = b'\x00\x00'
        hask_id = hdsk_req_buffer[8:12]
        ctt_cnt = b'\x00\x01'
        gid_context = b'\x00\x0a'
        prio = b'\x07'
        unknown = b'\x00'
        ap_num = b'\x00\x01'
        role = b'\x04'
        end = b'\x00'
        hdsk_ans_message = head + version + type_ + length + result + hask_id + \
                           ctt_cnt + gid_context + prio + unknown + ap_num + role + end

        return hdsk_ans_message

    # 数据备份报文
    def hb_data(self):
        ctx_msg = b'\x01'
        gid_context = b'\x00\x0a'
        len1 = b'\x00\x23'
        string = b'aaaaabbbbbaaa'  # 13字节
        num = b'\x00\x00\x00'
        len2 = b'\x00\x00\x00\x0e'
        ctx_data_msg = b'\x00'
        end = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'

        hb_data_buffer = ctx_msg + gid_context + len1 + string + num + len2 + ctx_data_msg + end

        return hb_data_buffer

    # 数据报备模拟报文
    def hb_test_data(self):
        ctx_msg = b'\x01'
        gid_context = b'\x00\x0a'
        len1 = b'\x00\x23'
        string = b'\x73\x63\x63\x2d\x77\x6c\x61\x6e\x2d\x68\x62\x00\x00'
        num = b'\x00\x00\x00'
        len2 = b'\x00\x00\x00\x0e'
        ctx_data_msg = b'\x00'
        end = b'\x04\x00\x00\x00\x01\x02\x00\x00\x00\x04\x00\x00\x00\x25'

        hb_test_data_buffer = ctx_msg + gid_context + len1 + string + num + len2 + ctx_data_msg + end

        return hb_test_data_buffer

    # TCP链接通道
    def tcp_tunnel(self, dst_port, src_port):
        sock = socket.create_connection((self.dst_ip, dst_port), 60, (self.loc_ip, src_port))

        return sock

    # 两个TCP tunnel 
    # 调用两次
    def doub_tcp_tunnel(self):
        sock1 = self.tcp_tunnel(dst_port=6425, src_port=10000)
        sock2 = self.tcp_tunnel(dst_port=6435, src_port=10001)

        return sock1, sock2

    # UDP通道
    def build_connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # 创建一个socket
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.loc_ip, self.loc_port))

        return sock

    # 测试
    def test(self, hb_test_data_buffer_numm, interval):
        sock = self.build_connect()
        message_max_size = 1024
        echo_req_buffer = self.echo_req()
        dst_addr = (self.dst_ip, self.dst_port)
        # 执行两次探测
        while True:
            try:
                sock.sendto(echo_req_buffer, dst_addr)
                buffer, addr = sock.recvfrom(message_max_size)
                if struct.unpack('104B', buffer)[2:6] == (0, 2, 0, 1):
                    print('send echo_req_buffer')
                    break
            except:
                pass

        while True:
            try:
                buffer, addr = sock.recvfrom(message_max_size)
                echo_req_buffer = buffer
                self.times += 2
                echo_ack_buffer = self.echo_ack(echo_req_buffer)
            except:
                # pass
                print('no echo_req_buffer!')
            else:
                sock.sendto(echo_ack_buffer, addr)
                print('send echo_ack_buffer')
                break
        # 握手阶段
        while True:
            buffer, addr = sock.recvfrom(message_max_size)
            try:
                if struct.unpack('22B', buffer)[2:6] == (0, 2, 0, 2):
                    hdsk_req_buffer = buffer
            except:
                pass
            else:
                hdsk_ans_buffer = self.hdsk_ans(hdsk_req_buffer)
                sock.sendto(hdsk_ans_buffer, addr)
                sock.close()
                print('send hdsk_ans_buffer!')
                break
        try:
            sock1, sock2 = self.doub_tcp_tunnel()
        except:
            print('can not build tcp tunnel ')
        else:
            print('build tcp tunnel')
            hb_test_data_buffer = self.hb_test_data()

            log = open('log.txt', 'a')
            delay = (1 - 0.00012 * int(hb_test_data_buffer_num)) / int(hb_test_data_buffer_num)
            error = 0
            buffer_num = 0
            start_time = time.time()
            end_time = time.time()
            while end_time - start_time < interval:
                for i in range(int(hb_test_data_buffer_num)):
                    try:
                        sock1.sendall(hb_test_data_buffer)
                    except:
                        print('error')
                        error += 1
                    else:
                        buffer_num += 1
                    time.sleep(delay)
                end_time = time.time()
            log.write('ip为' + self.loc_ip + '共发送报文个数:' + str(buffer_num) + ',共发送字节数:' + str(
                40 * buffer_num) + ',发送报文错误的个数为:' + str(error) + '\n')
            log.close()


if __name__ == '__main__':
    loc_port = 7425
    dst_ip = '192.168.31.30'
    dst_port = 7425
    loc_ip = sys.argv[1]
    hb_test_data_buffer_num = int(sys.argv[2])
    interval = int(sys.argv[3])
    AC = AC_client(loc_ip, loc_port, dst_ip, dst_port)
    AC.test(hb_test_data_buffer_num, interval)
