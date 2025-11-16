import telnetlib
import socket
import time


class TelnetClient:
    def __init__(self, host, username, password, timeout=10):
        self.host = host
        self.username = username
        self.password = password
        self.timeout = timeout
        self.connection = None

    def connect(self):
        try:
            self.connection = telnetlib.Telnet(self.host, timeout=self.timeout)

            # 等待登录提示
            self.connection.read_until(b"login: ", timeout=self.timeout)
            self.connection.write(self.username.encode('ascii') + b"\n")

            if self.password:
                self.connection.read_until(b"Password: ", timeout=self.timeout)
                self.connection.write(self.password.encode('ascii') + b"\n")

            # 等待命令提示符
            time.sleep(1)  # 给系统一些时间处理
            self.connection.read_until(b"$ ", timeout=self.timeout)
            return True

        except socket.timeout:
            print("连接超时")
            return False
        except Exception as e:
            print(f"连接错误: {e}")
            return False

    def execute(self, command):
        if not self.connection:
            print("未建立连接")
            return None

        try:
            self.connection.write(command.encode('ascii') + b"\n")
            output = self.connection.read_until(b"$ ", timeout=self.timeout).decode('ascii')
            return output.split('\n')[1:-1]

        except Exception as e:
            print(f"执行命令错误: {e}")
            return None

    def close(self):
        if self.connection:
            self.connection.write(b"exit\n")
            self.connection.close()


# 使用示例
if __name__ == "__main__":
    # host = input("输入主机地址: ")
    # username = input("输入用户名: ")
    # password = getpass.getpass("输入密码: ")

    client = TelnetClient("192.168.1.17", "anlan", "123456")

    if client.connect():
        print("\n连接成功")

        # 执行ps命令
        ps_output = client.execute("ls /home/anlan/Desktop/airtrace")
        if ps_output:
            for line in ps_output:
                print(line)

        # 可以继续执行其他命令
        # df_output = client.execute("df -h")

        client.close()