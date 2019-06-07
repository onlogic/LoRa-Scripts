import serial
import logging
import time
import struct
import random
import string
import collections
import binascii

LOGGER = logging.getLogger("testsample.lora")

TEST_HEADER = "LSLORABETA@"


def checksum_hex_bytes(data):
    sums = 0
    data = list(data)
    while len(data) > 1:
        sums += int(data.pop(0) + data.pop(0), 16)

    return "{:02x}".format(sums % 0x100)


def generate_test_payload(frontload=None, byte_length=32):
    """
    This function combines the frontload parameter with random characters to simulate a LoRa packet.
    :param frontload: a string of ascii or byte characters to be used as the frontend of the payload
    :param byte_length: Sets the overall length of the payload. Random data will be generated to make
        the payload the requested size
    :return: payload: string of hex Bytes limited to the specified byte_length
    """
    if type(frontload) is str:
        payload = frontload[:byte_length]
    else:
        payload = ""

    while len(payload) < byte_length:
        payload += random.choice(string.ascii_letters)
    return payload.encode("utf-8")


class LoraFrame(object):
    # This class is used to create the command string that will be sent to the LoRa card

    # This commands list is for aliasing the command codes
    commands = {'23': 'START_FRAME',
                '30': 'START',
                '31': 'STOP',
                '32': 'SEND',
                '33': 'RECEIVE',
                '34': 'RFCONFIG',
                '38': 'TXABORT',
                '39': 'TXSTATUS',
                '43': 'RXSTATUS',
                '0d': 'END_FRAME',
                '3a': 'VERSION',
                'ff': 'INVALID'}

    def __init__(self, command=None, length=None, payload=None):
        self._command = command if command is not None else ''  # This sets the command code
        self._length = length if length is not None else '0000'  # This sets the command length
        self._payload = payload if payload is not None else ''  # If the command is a send command this sets the payload
        self._checksum = None

    @property
    def checksum(self):
        """
        This creates the checksum needed to tell the LoRa card that the command is uncorrupted.
        :return: int - check sum value
        """

        if self._checksum is None:
            self._checksum = checksum_hex_bytes("23{}{}{}".format(self._command, self._length, self._payload))
        return self._checksum

    @property
    def data(self):
        """
        This function pulls the data from the frame, and sends it in the standard format.
        :return: string - hex info for LoRa card
        """

        return "23{}{}{}{}0d".format(self._command, self.length, self._payload, self.checksum)

    @property
    def length(self):
        """
        Returns the length of the payload.
        :return: string - length of the packet
        """

        return "{}{}".format(self._length[2:], self._length[0:2])

    @property
    def status(self):
        """
        This checks if the command is a send or receive message.
        :return: string - current stae of the LoRa card
        """

        if self._command in ["33", "32"]:
            if len(self._payload) == 2:
                # This ensures that the message was properly sent or received
                if self._payload[1] == '0':
                    msg = 'ACK'
                elif self._payload[1] == '1':
                    msg = 'NAK - error(0x{})'.format(self.payload[0])
                else:
                    msg = '{}'.format(self._payload[0])
                return msg
            else:
                return ''
        # This checks for the TX status from the card.
        elif self._command == "39":
            # If the payload is for a status update from the card these are the possible outcomes.
            if self._payload == "00":
                msg = "TX state unknown"
            elif self._payload == "01":
                msg = "TX modem is disabled"
            elif self._payload == "02":
                msg = "TX modem is active and waiting for commands"
            elif self._payload == "03":
                msg = "TX modem is loaded with a command"
            elif self._payload == "04":
                msg = "TX modem is currently transmitting"
            else:
                msg = "Unknown TX code"
            return msg

    def __str__(self):
        return "<23><{}><{}><{}><{}><0d>".format(self._command, self._length, self._payload, self.checksum)


class LoraPacketRX(object):
    # Object for parsing the data payload of a Lora RECEIVE Frame
    def __init__(self, rx_data=None):
        super(LoraPacketRX, self).__init__()
        self.data = rx_data
        if self._data is not None:
            self.parse()

    def parse(self):
        """
        This function organizes a received payload into its various component categories
        """

        hbytes = self._data.decode('hex')
        self._status            = hbytes[0:1].encode('hex')     # first byte is rx status
        self._transmit_frequency= hbytes[4:0:-1].encode('hex')  # next 4: IF Channel Frequency (reverse the bytes)
        self.if_chain           = hbytes[5:6].encode('hex')     # next 1: IF Chain packet received
        self.packet_status      = hbytes[6:7].encode('hex')     # next 1: Status of rx'd packet
        self.timestamp          = hbytes[7:11].encode('hex')    # next 4: time stamp
        self._rf_chain          = hbytes[11:12].encode('hex')   # next 1: RF Chain
        self._modulation        = hbytes[12:13].encode('hex')   # next 1: Modulation
        self.bandwidth          = hbytes[13:14].encode('hex')   # next 1: Bandwidth
        self._data_rate         = hbytes[14:18].encode('hex')   # next 4: data rate
        self._coding_rate       = hbytes[18:19].encode('hex')   # next 1: coderate
        self.rssi               = hbytes[19:23].encode('hex')   # next 4: RSSI
        self.snr_avg            = hbytes[23:27].encode('hex')   # next 4: SNR Average (Bb / Bb)
        self.snr_min            = hbytes[27:31].encode('hex')   # next 4: SNR Minimum (Bb / Bb)
        self.snr_max            = hbytes[31:35].encode('hex')   # next 4: SNR Max (Bb / Bb)
        self.crc                = hbytes[35:37].encode('hex')   # next 2: CRC
        self.payload_length     = hbytes[37:39].encode('hex')   # next 2: Payload Size
        self.payload_length_int = int(self.payload_length[::-1].encode('hex'), 16)
        self.payload_length     = hbytes[39:].encode('hex')     # Everything till the end is payload data

    @property
    def status(self):
        """
        Helper property used to interpret meaning of _status
        :return: tuple (rx_buffer, error_code)
        """

        bin_data = "{:08b}".format(int(self._status, 16))
        return int(bin_data[0:4], 2), int(bin_data[4:], 2)

    @property
    def data(self):
        """
        Returns the raw data for the packet
        :return: Hex byte string
        """
        return self._data

    @property
    def rx_status(self, val=None):
        """
        This function should warn the user of potential errors with the packet
        :param val: The hex status value of the packet
        :return: string - overflow issues or clean bill
        """
        if val is None:
            val = self.status[1]
        val = "{:04b}".format(val)

        msg = []

        if val[2] == '1':
            msg.append("RX Buffer Overflow")

        if val[3] == "1":
            msg.append("RX Buffer Overflow")

        if msg != []:
            return " & ".join(msg)
        else:
            return "RX Status OK"


class LoraPacketTX:
    # This class creates the needed elements to describe the header of a LoRa packet in hex digits.

    def __init__(self):
        self.Transmit_frequency = "6001c835"
        self.Transmit_mode = "00"
        self.Transmit_start_time = "00000000"
        self.RF_chain = "00"
        self.Tx_power = "1b"
        self.Modulation = "10"
        self.Modulation_bandwidth = "03"
        self.Data_rate = "10000000"
        self.Coding_rate = "01"
        self.Invert_polarity = "00"
        self.Frequency_deviation = "00"
        self.Preamble_length = "0600"
        self.CRC_Disable = "00"
        self.Implicit_header_enable = "00"
        self.payload = TEST_HEADER

    @property
    def payload_length(self):
        """
        Returns the length of the hex character payload
        :return: Hex digits
        """

        return struct.pack("<I", int(len(self.payload) / 2)).hex()

    def string_creation(self, payload=None):
        """
        This builds a string that can be passed to the lora card for sending a packet
        :param payload: String - contains the actual information contained in the packet
        :return: string - payload loaded with all the required perimeters
        """

        if payload is not None:
            self.payload = payload.hex()

        complete_string = self.Transmit_frequency + \
            self.Transmit_mode + \
            self.Transmit_start_time + \
            self.RF_chain + \
            self.Tx_power + \
            self.Modulation + \
            self.Modulation_bandwidth + \
            self.Data_rate + \
            self.Coding_rate + \
            self.Invert_polarity + \
            self.Frequency_deviation + \
            self.Preamble_length + \
            self.CRC_Disable + \
            self.Implicit_header_enable + \
            self.payload_length + \
            self.payload
        return complete_string


class occam_card(object):
    # This class creates the serial input need to connect the user to the LoRa card

    def __init__(self, com_port):
        self.frame_queue = []
        self.rx_packets = collections.deque(maxlen=30)
        self.com_port = com_port
        self._last_read = ""

        assert self.open_port(), "Failed to open Serial Port {}".format(com_port)

    def open_port(self, baudrate=9600, bytesize=8, parity=serial.PARITY_NONE, xonxoff=serial.XON,
                  stopbits=serial.STOPBITS_ONE, timeout=0):
        """
        This function opens the serial connection to the LoRa card.
        :param baudrate: int - baudrate of the connection to the card
        :param bytesize: int - expected byte size
        :return: boolean - declares if the connection has been made to the card
        """

        try:
            self.com = serial.Serial(self.com_port, baudrate=baudrate, bytesize=bytesize, parity=parity,
                                     stopbits=stopbits, timeout=timeout)
            return True
        except Exception as e:
            LOGGER.exception(e)
            return False

    def send_command(self, cmd, payload="", check_ack=True, timeout=10):
        """
        Method to send a specific command to the Lora Card. Frame start, length, and
        checksum are all automatically calculated.
        :param cmd: a two character string representing a hex byte. See LoraFrame._commands
        :param payload: a string of hex data representing the payload bytes
        :param check_ack: boolean that instructs the function to try and get an ACK after sending the command
        :param timeout:  integer representing the number of seconds we will wait for an ACK
        :return: confirmation of the packets getting sent.
        """

        if LoraFrame.commands.get(cmd, None) is not None:
            LOGGER.debug("Sending {} Command with Payload <{}>".format(LoraFrame.commands[cmd], payload))
        else:
            LOGGER.warning("Unknown Command {}".format(cmd))

        assert len(cmd) == 2, "Lora Commands are only one Byte. Cannot use {}".format(cmd)
        assert all(c in string.hexdigits for c in payload), "Command can only use Hexadecimal characters"
        assert len(payload) % 2 == 0, "Payload must be constructed as Bytes. ie It will have enough even string length."
        assert all(c in string.hexdigits for c in payload), "Payload can only use Hexadecimal characters."

        data = '23{}'.format(cmd)
        data += struct.pack("<I", int(len(payload) / 2)).hex()
        data += payload
        data += checksum_hex_bytes(data) + '0d'

        self.write_data(data)
        LOGGER.debug("Sending Data: {}".format(data))
        # The following chain of if statements is used to see the response from the card for a sent command
        if check_ack:
            for i in range(timeout):
                acked = None
                time.sleep(1)
                if self.check_buffer():
                    # serial buffer has been checked and the frames were parsed...
                    for i, frame in enumerate(self.frame_queue):
                        if frame._command == cmd and frame.status != "":
                            # we got a response for our command
                            if frame.status == 'ACK':
                                LOGGER.info("Command ({}) ACK!".format(cmd))
                                acked = True
                                break
                            else:
                                LOGGER.info("Command ({}) - {}!".format(cmd, frame.status))
                                acked = False
                                break
                        elif frame._command == 'ff':
                            LOGGER.warning("Module -> Host: Received INVALID Command.")
                            acked = False
                            break
                    if acked is not None:
                        LOGGER.debug("Frame ({}) removed from frame_queue".format(str(frame)))
                        self.frame_queue.pop(i)
                        return acked
            LOGGER.warning("Timeout ({}s): No response received for Command ({})!".format(timeout, cmd))
            return False
        else:
            return True

    def write_data(self, data):
        """
        This methods sends raw hex data to the Occam card.
        :param data: string of hex characters
        """

        try:
            self.com.write(data.decode('hex'))
        except Exception as e:
            LOGGER.exception(e)

    def check_buffer(self):
        """
        Reads data from the Lora card, and will be put onto the frame queue.
        :return: Boolean - describes if there are any frames in queue or not
        """

        if self.com.in_waiting:
            LOGGER.debug("Reading Data from Buffer.")
            self._last_read = self.com.read(self.com.in_waiting).encode('hex')
            found_frames = [fr for fr in parse(self._last_read)]
            if found_frames:
                self.frame_queue.extend(found_frames)
                return True
            return False

    @property
    def in_waiting(self):
        return self.com.in_waiting

    def ack_rx(self):
        """
        Lets the LoRa card know that it received a packet.
        """
        self.send_command('33', payload='00', check_ack=False)


def parse(data):
    """
    This function parses through hex bytes for the known frame syntax of the Lora card communication API,
    when a complete frame is found, it yields a LoraFrame object.
    :param data: Raw output from other Lora cards.
    """

    data = list(data)
    _started = False
    _command = None
    _payload = None
    _length = ''
    ilen = None

    while len(data) > 1:
        byt = data.pop(0) + data.pop(0)
        if not _started:
            if LoraFrame.commands.get(byt, None) == "START_FRAME":
                _started = True
            # The first bytes should be the start byte, but if we dont get a start byte, then we will throw stuff away
            # until we find a start byte
        else:
            if len(_length) == 0 and _command is None:
                # _length and _command have both not been started. Command comes after the start byte
                _command = byt
                LOGGER.debug("Parsing '{}' Command ({})".format(LoraFrame.commands.get(byt, "UNKNOWN"), byt))
            elif len(_length) < 4:
                # Populate _length (build it so that it becomes big-endian)
                _length = byt + _length
            else:
                # Here we have both the _command and _length so we should be parsing for the payload data
                ilen = ilen if ilen is not None else int(_length, 16)
                if ilen and _payload is None:
                    LOGGER.debug("Reading {} bytes of Payload".format(ilen))
                    _payload = byt + _length
                    ilen -= 1
                elif ilen > 0 and (len(_payload) / 2) < int(_length, 16):
                    # Payload has a non-zero length so we can get it
                    _payload += byt
                    ilen -= 1

                if ilen == 0 or len(data) == 4:
                    # Get checksum, varify the checksum byte
                    chkl = checksum_hex_bytes('23{}{}{}'.format(_command, _length, _payload))
                    LOGGER.debug("CHK: {} - Reported CHK: {}".format(chkl, "".join(data[0:2])))

                    if chkl == "".join(data[0:2]) and '0d' == "".join(data[2:4]):
                        fr = LoraFrame(_command, _length, _payload)
                        LOGGER.debug("Checksum Matched! ({}) - End of Frame found!".format(chkl))
                        LOGGER.debug(str(fr))

                        yield fr
                    else:
                        LOGGER.warning("Checksum mismatch! ({}) != ({}) or End-of-Frame not found ({})!".format("".join(data[0:2]), chkl, data[2:4]))

                    _started = False
                    _command = None
                    _payload = None
                    _length = ''
                    ilen = None


def receive_sample(lora_card, packet_header):
    """
    This is a basic loop that looks for a packet with a specific header then exits once found.
    :param lora_card: The initiated connection to your LoRa card
    :param packet_header: This is a unique header that lets the program know which packets are yours
    """
    run_sample = True

    while run_sample:
        remove_frames = []
        resp = lora_card.send_command('39')
        for i, frame in enumerate(lora_card.frame_queue):
            if frame._command == '33':
                lprx = LoraPacketRX(frame._payload)
                LOGGER.info("RX'd: {}".format(lprx.payload.decode('hex')))
                if packet_header in lprx.payload.decode('hex'):
                    LOGGER.info("Corresponding header found.")
                    run_sample = False
                    print(str(lprx.payload.decode('hex')))
                    lora_card.rx_packets.append(lprx)
                lora_card.ack_rx()
                remove_frames.append(i)

            for index in remove_frames:
                try:
                    lora_card.frame_queue.pop(index)
                except:
                    pass



def send_sample(lora_card, packet_header):
    """
    This sample code sends out a LoRa packet with an identifying header.
    :param lora_card: The initiated connection to your LoRa card
    :param packet_header: This is a unique header that identifies which packets are yours
    """

    test_payload = generate_test_payload(packet_header)
    LOGGER.info("Test Payload: {}".format(test_payload))
    resp = lora_card.send_command('39')  # This command check to make sure that the LoRa card is ready.

    lr_message = LoraPacketTX()
    lora_card.send_command('32', lr_message.string_creation(test_payload))

    resp = lora_card.check_buffer()

    time.sleep(5)
    lora_card.send_command("38", check_ack=False)

    LOGGER.info("Test complete.")


if __name__ == "__main__":
    logging.basicConfig(filename='lora.log',
                        level=logging.INFO,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    port = '/dev/ttyACM2'
    lora_card = occam_card(port)
    choice_var = ""
    packet_header = "U123456"

    resp = lora_card.send_command('30')

    while choice_var != '3':
        print("Please choose the sample application:")
        print("1) Receive sample")
        print("2) Send sample")
        print("3) Exit program")
        choice_var = input("Enter your choice: ")

        if choice_var == "1":
            receive_sample(lora_card, packet_header)
        elif choice_var == "2":
            send_sample(lora_card, packet_header)
        elif choice_var == "3":
            print("Exiting...")
        else:
            print("That is not a valid option, please reselect.")
