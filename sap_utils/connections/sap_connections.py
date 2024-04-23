class SAPConnection:
    def __init__(self, connection_name, connection_type, connection_from, connection_to, username, password_flag):
        self.connection_name = connection_name
        self.connection_type = connection_type
        self.connection_from = connection_from
        self.connection_to = connection_to
        self.username = username
        self.password_flag = password_flag

    def display_info(self):
        print("Connection Name:", self.connection_name)
        print("Connection Type:", self.connection_type)
        print("Connection From:", self.connection_from)
        print("Connection To:", self.connection_to)
        print("Connection username:", self.username)
        print("Connection Password saved:", self.password_flag)
