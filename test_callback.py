import snap7
import time
def cb(event):
    print("Read event!")

s = snap7.server.Server()
s.set_read_events_callback(cb)
s.start()
print("Connecting...")
c = snap7.client.Client()
c.connect('127.0.0.1', 0, 1)
c.db_read(1, 0, 16)
print("Connected!")
c.disconnect()
time.sleep(1)
s.stop()
