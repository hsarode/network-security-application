
# Stream class to handle the buffered data.
class Stream:
    def __init__(self,s):
        self.socket = s
        self.stream = b''

    def get_data(self,n):
        while len(self.stream) < n:
            try:
                data = self.socket.recv(1024)
                if not data:
                    data = self.stream
                    self.stream = b''
                    return data
                self.stream += data
            except:
                print('end of bytes received')
        data,self.stream = self.stream[:n],self.stream[n:]
        return data

    def send_data(self,data):
        self.socket.sendall(data)

    def get_str_data(self):
        try:
            while b'\x00' not in self.stream:
                data = self.socket.recv(1024)
                if not data:
                    return ''
                self.stream += data
        except:
            print('Error occured during reading bytes')
        data,_,self.stream = self.stream.partition(b'\x00')
        return data.decode()

    def send_str_data(self,s):
        if '\x00' in s:
            raise ValueError('string contains delimiter(null)')
        self.socket.sendall(s.encode() + b'\x00')