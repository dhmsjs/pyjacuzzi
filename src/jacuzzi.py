""" This module extends balboa.py to work instead with Jacuzzi
spas. 

It uses pybalboa-0.13 from https://github.com/garbled1/pybalboa.

I chose to extend pybalboa so that I could leverage the already-proven
WiFi and protocol parsing behavior in pybalboa. This dependency turns
out to be pretty light; it would not take major effort to decouple
jacuzzi.py from pybalboa. Still, I am deeply indebted to 

garbled1 (https://github.com/garbled1/pybalboa)
natekspencer (https://github.com/natekspencer)
ccutrer (https://github.com/ccutrer/balboa_worldwide_app/wiki)

along with several others here unnamed, who have helped reverse engineer
balboa hot tub control systems and their many rebranded derivatives.

Note that as of Jan 2023 pybalboa has undergone significant revisions
beyond version 0.13. I doubt jacuzzi.py will work with anything later than
v0.13 without careful attention -- which given the light dependency, is
probably not worth the effort.
"""
import asyncio
import errno
import logging
import time
import warnings

# if the parent balboa module is not installed, use a local copy
# instead.
#
# We use the "from...*" construct here so that all objects in balboa 
# (without a leading underscore anyway) become available as local
# objects; i.e. they can only be referenced without the "balboa."
# module prefix. 
#
# This is not generally a good idea because it increases the chances
# of duplicate names clashing unintentionally.  Requiring you to use the
# "balboa." prefix would prevent this.
#
# Here we use it intentionally to cleanly reference or override balboa
# module objects when they need to be different for Jacuzzi systems.
try:
    from balboa import *
except:
    from .balboa import *

from enum import Enum


class ConnectionStates(Enum):
    """ enum types for Wifi connection states. """
    Disconnected = 0
    Connecting = 1
    Connected = 2


# TODO: This is defined here only to eliminate a runtime error; 
# we may be able to remove references to this; probably not needed
# for jacuzzi spas.
NO_CHANGE_REQUESTED = -1

# Add unique enumerated constants for Jacuzzi-specific message types.
#
# These constants are NOT the message type values themselves. They are
# just sequentially enumerated constants used to uniquely identify
# each message type.
#
# Differences between Balboa and Jacuzzi systems:
#   The Balboa BMTR_STATUS_UPDATE msg type field is 0x13 instead of 0x16
#   The Balboa BMTR_FILTER_INFO_RESP msg type field is 0x27 instead of 0x23
#   The Balboa BMTS_PANEL_REQ msg type field is 0x22 instead of 0x19
#   The Balboa BMTR_SYS_INFO_REQ msg type field is 0x24 instead of 
#     0x1C (PLNK_SECONDARY_FILTER_RESP)
#   There is no PRIMARY_FILTER_RESP msg type or similar in Balboa systems
#   There is no PUMP_STATE_RESP msg type or similar in Balboa systems
#   The Balboa BMTR_SETUP_PARAMS_RESP msg type field is 0x25 instead of 0x1E

PLNK_STATUS_UPDATE = NROF_BMT
PLNK_FILTER_INFO_RESP = NROF_BMT + 1
PLNK_PANEL_REQ = NROF_BMT + 2
PLNK_SECONDARY_FILTER_RESP = NROF_BMT + 3
PLNK_PRIMARY_FILTER_RESP = NROF_BMT + 4
PLNK_PUMP_STATE_RESP = NROF_BMT + 5
PLNK_SETUP_PARAMS_RESP = NROF_BMT + 6
PLNK_LIGHTS_UPDATE = NROF_BMT + 7

# Recognize encrypted status packets
PLNK_C4_STATUS_UPDATE = NROF_BMT + 8
PLNK_CA_LIGHTS_UPDATE = NROF_BMT + 9

# Override pybalboa text strings for Jacuzzi-specific differences:

text_tscale = ["Fahrenheit", "Celsius"]   # Just to fix the misspelling


class JacuzziSpaWifi(BalboaSpaWifi):
    """Extends BalboaSpaWifi to work with Jacuzzi spas instead. """

    def __init__(self, hostname, port=BALBOA_DEFAULT_PORT):
        super().__init__(hostname, port)      
        self.connection_state = ConnectionStates.Disconnected

        # Balboa systems can receive ("auto detect") configuration info from
        # the actual spa. So the BalboaSpaWifi class waits to receive this
        # configuration info before it will start working.
        #
        # Jacuzzi spas don't seem to tell us their config -- and if really
        # true then auto detecting is not possible. So for now we will just
        # set up some default config values.
        #
        # TODO: implement some sort of configuration methods for Jacuzzi spas.
            
        self.pump_array = [0, 2, 1, 0, 0, 0]    # Jet pumps 1 and 2 only
        self.nr_of_pumps = 2
        self.circ_pump = 1
        self.tempscale = self.TSCALE_F
        self.timescale = self.TIMESCALE_12H 
        self.temprange = self.TEMPRANGE_HIGH
        
        # Initialize low range min and max temperatures as [°F, °C]
        # (but not used in Jacuzzi spas)
        self.tmin[0] = [40, self.to_celsius(40)]
        self.tmax[0] = [104, self.to_celsius(104)]

        # Initialize high range min and max temperatures as [°F, °C]
        self.tmin[1] = [40, self.to_celsius(40)]
        self.tmax[1] = [104, self.to_celsius(104)]

        self.filter_mode = self.FILTER_1
        self.heatmode = 0
        self.filter1_hour = 0
        self.filter1_duration_hours = 8
        self.filter2_enabled = 0

        self.isSecondaryOn = 0
        self.isPrimaryOn = 0
        self.isBlowerOn = 0
        self.isUVOn = 0

        self.pump3State = 0
        self.pump2State = 0
        self.pump1State = 0
        self.pump0State = 0
     
        # Setup some model specific values
        # TODO: remove any that are not relevant to Jacuzzi spas
        self.day = -1
        self.month = -1
        self.year = -1

        self.dayOfMonth = 0
        self.currentMonth = 0
        self.currentYear = 0

        self.temp2 = -1
        self.manualCirc = -1
        self.autoCirc = -1
        self.unknownCirc = -1
        self.heatState2 = -1      
        self.displayText = -1
        self.heatMode = -1
        self.UnknownField3 = -1
        self.UnknownField9 = -1

        self.tempLock = -1
        self.settingsLock = -1
        self.accessoriesLock = -1
        self.serviceLock = -1
        # panelLock is balboa.py's name for settingsLock
        self.panelLock = self.settingsLock
        
        self.lightBrightness = 0
        self.lightMode = 0
        self.lightR = 0
        self.lightG = 0
        self.lightB = 0
        self.lightCycleTime = 0

        self.statusByte17 = 0
        self.filter1StartHour = 0 
        self.filter1DurationHours = 0
        self.filter1Freq = 0

        self.filter2Mode = 0

        # Support for encrypted message packets
        self.encrypted_comm = False
        self.encrypted_settemp = None
        self.encrypted_settemp_task = None

        # In the J-235 spa the light cycle time for "blend" mode
        # is only 1 change per second. Apparently in Balboa spas
        # there are two speeds: 1 change per second and 2 changes
        # per second (I think).
        # self.lightCycleTime = 1 # In seconds. 

        # The Prolink Wifi module always has channel address 0x0A
        # but it's still a class attribute here in order to support
        # future custom (non-Prolink) RS485-to-TCP devices which may
        # need different channel addresses.
        self.channel = 0x0A

        # setup some specific items that we need that the base class
        # doesn't.
        # TODO: Not used now; probably can be removed
        self.target_pump_status  = [NO_CHANGE_REQUESTED, NO_CHANGE_REQUESTED, NO_CHANGE_REQUESTED,
                                    NO_CHANGE_REQUESTED, NO_CHANGE_REQUESTED, NO_CHANGE_REQUESTED]
        self.targetTemp = NO_CHANGE_REQUESTED
        self.checkCounter = 0
        self.CAprior_status = None

        self.prev_chksums = {}
        self.config_loaded = True   # Done with configuration

        # 2nd temperature sensor. This is apparently in the plumbing
        # not in the tub itself as the primary sensor is. So this
        # one tells you what the water temperature in the pipes is.
        self.statusByte21 = 0
  
    def decrypt(self, packet: bytearray) -> bytearray:
        """ Returns a decrypted version of type "C4" panel status and type
        "CA" LED status message packets sent by "encrypted" control boards
        for Jacuzzi and Sundance spas. 

        Also updates the packet checksum byte so that any decrypted packet
        is still a vald message packet.

        Returns all other message packet types unchanged.

        The encryption algorithm used by Jacuzzi and Sundance is a type of
        "XOR Cipher" where each byte of the message data is XORed with the
        corresponding byte of an equal-length cipher string. In this case
        the bytes of the cipher string are just a decreasing sequence derived
        from the length of the message data.  

        In addition the encrypted packet includes an extra prefix byte which
        is used to form a constant value that is also XORed with each byte
        of the message data.  

        As is typical with XOR cipher encryption, you would use the same
        algorithm to both encrypt and decrypt the nessage. 

        Typical encrypted C4 packet:
        byte #:    000102030405 060708 09101112 13141516 17181920 21222324 25262728 29303132 33343536 37 3839
        encrypted: 7e26ffafc41f 151b1a 1516a6ec 16107310 2d0c470b 68080a1d 05012206 b0000368 673c3f3e 39 937e
        decrypted: 7e26ffafc41f 0d0000 080ab9f2 07006002 3818501d 61000117 080d2d08 b100006a 62383838 00 8a7e
        """
        # Quit if the packet is too short
        if len(packet) < 7:
            return packet
        
        # Encrypted packets have an extra byte that we use to form the first key value
        packet_type = packet[4]
        if packet_type == 0xc4:      # Status update packet
            key1 = packet[5] ^ 0x19
        elif packet_type == 0xca:    # Lights update packet
            key1 = packet[5] ^ 0x59
        elif packet_type == 0xcc:    # Button command packet
            key1 = packet[5] ^ 0xdf
        else:
            # Done if not an encrypted message type
            return packet

        # Received an encrypted packet so we must be using encrypted communications
        self.encrypted_comm = True
     
        # The second key value forms a cipher string which is a string of the same 
        # length as the encrypted data, and whose byte values are each decremented by
        # one from the previous, modulo 64.
        HEADER_LENGTH = 5
        packet_length = packet[1]
        key2 = packet_length - HEADER_LENGTH - 2

        # Just in case the packet we were given is an immutable "bytes" array
        # we will convert it to a (mutable) bytearray type.
        packet = bytearray(packet)

        # Apply both keys to each encrypted value and save the decrypted result
        # back into the original packet.
        for i in range(6, packet_length):
          key2 = (key2 - 1) % 64
          packet[i] = packet[i] ^ key1 ^ key2

        # Force the "extra" encryption byte to zero just so packet checksums
        # will only change when the actual packet data fields change.
        packet[5] = 0

        # Calculate a new checksum over entire decrypted packet and save it as
        # the new packet checksum.
        packet[-2] = self.balboa_calc_cs(packet[1:packet_length], packet_length - 1)
        return packet

    def encrypt(self, packet: bytearray) -> bytearray:
        """ Returns an encrypted version of a command message packet for those
        packet types that have an encrypted equivalent. The prime example of this
        is the "button code" type set by topside panels whenever you press a
        panel button. 

        The given packet should be a complete message packet including the start
        and end flags (0x7e). If the message type does not have an equivalent
        encrypted version, this method will return the given packet unchanged. 
        """

        # Quit if the packet is too short.
        if len(packet) < 7:
            return packet
        
        # Get a dictionary of encryptable message types where each element
        # is in the form of unencrypted_type: encrypted_equivalent.
        etypes = {
                  0x11: 0xcc, # Balboa unencrypted button control message type
                  0x17: 0xcc, # Jacuzzi unencrypted pump 1-3 control message type
                  0x1a: 0xcc, # Jacuzzi unencrypted pump 4-6 control message type
                  0x1b: 0xcc, # Jacuzzi Send Primary Filter Request message type
                  0x20: 0xcc, # Balboa and Jacuzzi Set Target Temp message type
                 }

        # Quit if this packet type has no encrypted equivalent
        packet_type = packet[4]
        if packet_type not in etypes:
            return packet

        # Just in case the packet we were given is an immutable "bytes"
        # array we will convert it to a (mutable) bytearray type.
        packet = bytearray(packet)

        # Write the new encrypted packet type into the packet.
        packet[4] = etypes[packet_type]

        # Insert the extra encryption key byte into the packet. For now
        # the key byte is a simple constant, and add 1 to the packet
        # length byte and update the local packet_length variable
        # with the new length value.
        packet.insert(5, 0x00)
        packet[1] += 1
        packet_length = packet[1]

        # Encrypt the new packet by "decrypting" the unencrypted message
        # data. (XOR ciphers are symmetric.)
        packet = self.decrypt(packet)
     
        # Calculate a new checksum for the new, encrypted packet and save
        # it in the packet.
        packet[-2] = self.balboa_calc_cs(packet[1:packet_length], packet_length - 1)
        return packet

    def has_changed(self, data):
        """ Returns True if this message packet is different from
        the previous message of the same message type value.

        data is a byte array that must contain the entire new 
        message packet including start and end flag bytes.
        """
        # Since it is possible for different data sets to have the
        # exact same checksum value, using checksum comparison to
        # detect a change in data can result in false negatives --
        # i.e. a change in the message that we miss because the
        # checksums still match.  However the probability of that is
        # low and the cost of missing a change is also low, so for
        # now this seems good enough.  
        #
        # If you want to guarantee no false negatives, then the brute
        # force method used in balboa.py (saving a copy of the entire
        # message packet and comparing that byte by byte to the new
        # one) will give you what you want.
        changed = True
        mtval = data[4]
        mchk = data[-2]
        if mtval in self.prev_chksums and mchk == self.prev_chksums[mtval]:
            changed = False
            self.log.debug("No chg in msg of type 0x{:02X}".format(mtval))
        else:
            # self.log.info("Got new msg of type 0x{:02X}".format(mtval))
            self.log.info('New msg: {}'.format(data.hex()))
        self.prev_chksums[mtval] = mchk
        return changed

    async def send_mod_ident_req(self):
        """ Overrides parent method just to add debug logging. """
        self.log.debug("Requesting module ID (msg type value 0x04)")
        await super().send_mod_ident_req()

    async def send_temp_change(self, newtemp):
        """ Overrides the parent method to support encrypted spa controllers """
        # Check if the new temperature is valid for the current heat mode
        if (
            newtemp < self.tmin[self.temprange][self.tempscale]
            or newtemp > self.tmax[self.temprange][self.tempscale]
        ):
            self.log.error("Attempt to set temperature outside of heat mode boundary")
            return

        if not self.encrypted_comm:
            if self.tempscale == self.TSCALE_C:
                newtemp *= 2.0
            await self.send_message(*mtypes[BMTS_SET_TEMP], int(round(newtemp)))
        else:
            # Encrypted controllers do not seem to support a command to set the
            # the target temperature to an arbitrary value. Instead it seems the
            # only way to change setpoint is to send a series of "Temp Up" or 
            # "Temp Down" button commands until the controller setpoint equals
            # the new target setpoint value.
            #
            # We do this by starting an asynchronous task to periodically
            # send Temp Up or Temp Down button commands until the controller
            # reports a setpoint temperature that is equal to newtemp.

            async def _adjust_encrypted_settemp():
                # This local coroutine asynchronously sends Temp Up or 
                # Temp Down button commands until the controller's 
                # setpoint temperature equals the new setpoint temperature.
                # It must be defined before referencing it in the call to
                # asyncio.create_task() below.

                settemp_changed = True
                while True:
                    # If we lost connection then just end the coroutine.
                    if not self.connected:
                        self.encrypted_settemp_task = None
                        return
                    # Only send a new button command after the previous
                    # one has been effective.
                    if settemp_changed:
                        # Remember the new setpoint temp
                        cursettemp = self.settemp

                        # Decide which direction to go
                        reqd_change = self.encrypted_settemp - cursettemp
                        if reqd_change >= 1:
                            btncode = 0x01
                        elif reqd_change <= -1:
                            btncode = 0x02
                        else:
                            # We are within 1 degree of setpoint so end this
                            # coroutine.
                            self.encrypted_settemp_task = None
                            return

                        # Send a new button command to change setpoint temp.
                        # This unencrypted button command will be converted
                        # to an encrypted version by send_message()
                        data = bytearray(4)
                        data[0] = self.channel
                        data[1] = 0xBF
                        data[2] = 0x1A 
                        data[3] = btncode
                        await self.send_message(*data)

                    # Wait a bit before checking the new setpoint temp
                    await asyncio.sleep(1.0)
                    settemp_changed = cursettemp != self.settemp

            # Save the new target setpoint temperature
            self.encrypted_settemp = newtemp
            # Start the settemp adjustment task if it is not already running
            if self.encrypted_settemp_task is None:
                self.encrypted_settemp_task = asyncio.create_task(_adjust_encrypted_settemp())

    async def send_filter1_cycle_req(self):
        """ Sends a request for Primary Filter Cycle Info. """
        await self.send_panel_req(1, 0)

    async def send_filter2_cycle_req(self):
        """ Sends a request for Secondary Filter Cycle Info. """
        await self.send_panel_req(2, 0)

    async def send_panel_req(self, ba, bb):
        """Overrides the parent method to accommodate differences
        in the Prolink message format.

        ba and bb specify the type of panel request to send
        """
        # The only difference between Balboa and Jacuzzi panel request
        # message packets (apart from type value itself) is that the
        # Jacuzzi message packet does not have the extra byte field
        # (always 0x00?) between the ba and bb panel request values.
        #
        # Example: 7E 07 0A BF 19 01 00 XX 7E 
        # (XX = calculated checksum)
        data = bytearray(5)
        data[0] = self.channel
        data[1] = 0xBF
        data[2] = 0x19      # Was 0x22 for Balboa
        data[3] = ba
        data[4] = bb

        # send_message() will append the start and end flags, the length
        # and the checksum.
        await self.send_message(*data)

    async def _send_lock_req(self, typecode):
        # This local routine sends a command to lock
        # or unlock the spa control panel. Tested on a 
        # Jacuzzi J-235 tub. May be different on other
        # makes & models.
        #
        # typecodes from the Prolink app (but these are wrong!!):
        #     81 = 0x51 = lock temperature 
        #     41 = 0x29 = unlock temperature 
        #     82 = 0x52 = lock spa 
        #     42 = 0x2A = unlock spa 
        #
        # What really happens is this:
        #     0x80 = is ignored
        #     0x40 = is ignored
        #     0x81 = sets bit 2 of lock status byte ==> locks settings
        #     0x41 = clears bit 2 of lock status byte ==> unlocks settings
        #     0x82 = sets bit 1 of lock status byte ==> locks accessories
        #     0x42 = clears bit 1 of lock status byte ==> unlocks accessories
        #     0x84 = sets bit 0 of lock status byte ==> service lock
        #     0x44 = clears bit 0 of lock status byte == service unlock
        #     0x88 = is ignored
        #     0x48 = is ignored
        #     0x21 = is ignored
        #     0x11 = is ignored
        #     0x22 = is ignored
        #     0x12 = is ignored
        #     0x24 = is ignored
        #     0x14 = is ignored
        #     0x28 = is ignored
        #     0x18 = is ignored
        #     0x00 = is ignored
        #     0x01 = is ignored
        #     0xFF = is ignored
        #     0x55 = is ignored
        #     0xAA = is ignored
        #
        # When someone locks temperature changes from the topside panel,
        # bit 3 of the lock status byte gets set, and you cannot change
        # temperature setpoint from either the topside panel or jacuzzi.py.
        #
        # The way to clear any lock condition from the topside panel is 
        # to press and hold down the menu button for at least 10 seconds.
        # The topside panel display will then tell you which lock condition
        # it has cleared.
        #
        # The typecodes above can set and clear bits 0, 1 and 2 of the
        # lock status byte. But none will set or clear bit 3, yet it can
        # be set and cleared from the topside panel. 
        #
        # Thus it is currently not possible to clear a temperature setpoint
        # lock using jacuzzi.py.
        #
        # Example: 7E 0A 0A BF 1F 51 00 00 00 00 XX 7E 
        # (XX = calculated checksum)
        data = bytearray(8)
        data[0] = self.channel
        data[1] = 0xBF
        data[2] = 0x1F
        data[3] = typecode
        data[4] = 00
        data[5] = 00
        data[6] = 00
        data[7] = 00

        # send_message() will append the start and end flags, the length
        # and the checksum.
        await self.send_message(*data)

    # Apparently temperature changes cannot be locked and unlocked
    # remotely. They can be locked and unlocked from the topside
    # panel though. (See above.)
    async def lock_temp(self):
        """ Prevent changes to the temperature setpoint """
        await self._send_lock_req(0x88) # 0x88 doesn't work

    async def unlock_temp(self):
        """ Allow changes to the temperature setpoint """
        await self._send_lock_req(0x48) # 0x48 doesn't work

    async def lock_settings(self):
        """ Prevent any changes to the spa """
        await self._send_lock_req(0x81)

    async def unlock_settings(self):
        """ Allow changes to the spa """
        await self._send_lock_req(0x41)

    async def lock_accessories(self):
        """ Prevent any changes to accessories """
        await self._send_lock_req(0x82)

    async def unlock_accessories(self):
        """ Allow changes to accessories """
        await self._send_lock_req(0x42)

    async def lock_service(self):
        """ Prevent any pumps from running (for servicing) """
        await self._send_lock_req(0x84)

    async def unlock_service(self):
        """ Allow pumps to run (after servicing) """
        await self._send_lock_req(0x44)

    async def set_time(self, new_time, timescale=None):
        """ Overrides the parent method to set time on a Jacuzzi spa.
        Jacuzzi spa controllers do not switch to 12 hour timescale,
        so this method override ignores the timescale field.
        """
        # sanity check
        if not isinstance(new_time, time.struct_time):
            return

        data = bytearray(8)
        data[0] = self.channel
        data[1] = 0xBF
        data[2] = 0x18      # Was 0x21 for Balboa

        # Keep the date fields unchanged. The spa control system
        # will ignore this command if the upper 4 bits of the current
        # month are not all set to 1.
        data[3] = self.currentMonth | 0xF0
        data[4] = self.dayOfMonth
        data[5] = self.currentYear - 2000

        # In balboa spas setting bit 7 of the hour value will switch the 
        # spa time to 12 hour format. Jacuzzi spa controllers ignore this
        # bit though, so Jacuzzi spas will only operate in 24 hour mode.
        data[6] = new_time.tm_hour
        data[7] = new_time.tm_min

        # send_message() will append the start and end flags, the length
        # and the checksum.
        await self.send_message(*data)

    async def set_date(self, new_date, timescale=None):
        """ Sets the current date on a Jacuzzi spa. Since balboa
        spas do not have an internal date, there is no equivalent
        method in balboa.py.
        """
        # sanity check
        if not isinstance(new_date, time.struct_time):
            return

        data = bytearray(8)
        data[0] = self.channel
        data[1] = 0xBF
        data[2] = 0x18      # Was 0x21 for Balboa

        # Update the Set Time command date fields. The Jacuzzi spa
        # control system will ignore this command if the upper 4
        # bits of the current month are not all set to 1.
        data[3] = new_date.tm_mon | 0xF0
        data[4] = new_date.tm_mday
        data[5] = new_date.tm_year - 2000

        # Leave the time fields unchanged
        data[6] = self.time_hour
        data[7] = self.time_minute

        # send_message() will append the start and end flags, the length
        # and the checksum.
        await self.send_message(*data)

    async def change_pump(self, pump, newstate):
        """Overrides the parent method to accommodate differences
        in the Prolink message type fields.

        pump identifies the pump to change. 
        """
        
        # Each message sent emulates a button press on the Jacuzzi
        # topside control panel. So if a pump has two speeds for
        # example, then each message will effect one step through
        # the cycle of 0ff-low-high-off.
        #
        # The only difference between Balboa and Jacuzzi change pump
        # message packets (apart from type value itself) is that the
        # Jacuzzi type field has type field 0x17 for pumps 1 through 3
        # instead of 0x1A
        #
        # Example: 7E 06 0A BF 17 04 XX 7E 
        # (XX = calculated checksum)

        # sanity check
        if (
            pump > MAX_PUMPS
            or newstate > self.pump_array[pump]
            or self.pump_status[pump] == newstate
        ):
            return

        if pump == 1 or pump == 2 or pump == 3:
            mtype = 0x17
        else:
            mtype = 0x1A
        pumpcode = pump + 3

        data = bytearray(4)
        data[0] = self.channel
        data[1] = 0xBF
        data[2] = mtype      # Was 0x11 for balboa
        data[3] = pumpcode

        # calculate how many times to push the button
        iter = max((newstate - self.pump_status[pump]) % (self.pump_array[pump] + 1), 1)
        # now push the button that number of times
        for i in range(0, iter):
            # send_message() will append the start and end flags, the length
            # and the checksum.
            await self.send_message(*data)
            await asyncio.sleep(1.0)

    async def change_light(self, newmode):
        """Overrides the parent method to accommodate differences
        in the Prolink message type fields.
        """

        # Note that this is the same message type as brightness
        # control, with only slight differences in content.
        data = bytearray(11)
        data[0] = self.channel
        data[1] = 0xBF
        data[2] = 0x21     # Was 0x11 for balboa
        data[3] = 0x1F     # = 0x2F for brightness
        data[4] = newmode
        data[5] = 0x00
        data[6] = 0x00
        data[7] = 0x00
        data[8] = 0x00
        data[9] = 0xFF     # Brightness field
        data[10] = 0x00

        # send_message() will append the start and end flags, the length
        # and the checksum.
        await self.send_message(*data)

    async def change_brightness(self, newlevel):
        """Sends a command to change the LED brightness level."""

        # Note that this is the same message type as light mode
        # control, with only slight differences in content.
        data = bytearray(11)
        data[0] = self.channel
        data[1] = 0xBF
        data[2] = 0x21     # 0x21 is BMTS_SET_TIME for balboa
        data[3] = 0x2F     # = 0x1F for light mode control 
        data[4] = 0x01     # Mode field
        data[5] = 0x00
        data[6] = 0x00
        data[7] = 0x00
        data[8] = 0x00
        data[9] = newlevel # Brightness value
        data[10] = 0x00

        # send_message() will append the start and end flags, the length
        # and the checksum.
        await self.send_message(*data)

    async def change_filter1_cycle(self, starthour, durationhrs, frequency):
        """Sends a command to change the primary filter cycle
        start hour, duration and frequency (number of cycles per day).
        """

        # Note that this message type is also received by the app in response
        # to it sending the spa a Panel Request message of either the
        # "Filter Cycles" or "Primary Filtration" types.
        #
        # The Prolink app code sends a packet that does not include the frequency byte.
        # The spa controller does accept the packet without that byte, but seems to
        # lose communication temporarily, and then assume the frequency is 01 (1 cycle
        # per day).  Adding the frequency parameter to the packet does work too and does
        # not seem to cause a loss of communication.
        data = bytearray(6)
        data[0] = self.channel
        data[1] = 0xBF     # "PF" byte (always either 0xAF or 0xBF)
        data[2] = 0x1B     # BMTR_FILTER_INFO_RESP = 0x23, BMTS_FILTER_REQ = 0x22 for balboa
        data[3] = starthour
        data[4] = durationhrs
        data[5] = frequency

        # send_message() will append the start and end flags, the length
        # and the checksum.
        await self.send_message(*data)

        # Yield a bit while the spa acts on the request
        await asyncio.sleep(0.1)

        # Now request an update of current filter cycle info
        # so the UI can see the change.
        await self.send_filter1_cycle_req()

    async def change_filter2_cycle(self, mode):
        """Sends a command to change the secondary filter cycle
        mode between "Holiday", "Light" and "Heavy" modes. The
        mode values are 0, 1 and 2 respectively.
        """
        # This is essentially the same format as the filter info
        # response message sent by the spa controller to report
        # the current secondary filter mode value.
        data = bytearray(6)
        data[0] = self.channel
        data[1] = 0xBF     # "PF" byte (always either 0xAF or 0xBF)
        data[2] = 0x1C     # BMTR_FILTER_INFO_RESP = 0x23, BMTS_FILTER_REQ = 0x22 for balboa
        data[3] = mode
        data[4] = 0
        data[5] = 0

        # send_message() will append the start and end flags, the length
        # and the checksum.
        await self.send_message(*data)

        # Yield a bit while the spa acts on the request
        await asyncio.sleep(0.1)

        # Now request an update of current filter cycle info
        # so the UI can see the change.
        await self.send_filter2_cycle_req()

    async def send_message(self, *bytes):
        """ Overrides parent method only to change log messaging
        and to add support for encrypted command messages.
        """
        # if not connected, we can't send a message
        if not self.connected:
            return

        message_length = len(bytes) + 2
        data = bytearray(message_length + 2)
        data[0] = M_STARTEND
        data[1] = message_length
        data[2:message_length] = bytes
        data[-2] = self.balboa_calc_cs(data[1:message_length], message_length - 1)
        data[-1] = M_STARTEND

        if self.encrypted_comm:
            data = self.encrypt(data)

        self.log.info(f"Sending: {data.hex()}")
        try:
            self.writer.write(data)
            await self.writer.drain()
        except Exception as e:
            self.log.error(f"Error sending message: {e}")
 
    def parse_status_update(self, data):
        """ Override balboa's parsing of a status update from the spa
        to handle Jacuzzi differences. 

        Many of the field values are similar between Balboa and Jacuzzi,
        but their position in the message packet is often different.

        The spa spams these messages out at a very high rate of speed.

        Unlike the overridden version in balboa.py, this routine does not
        check to see if config has been loaded already. Thus it does not
        need the async prefix.  Similarly it does not check to see if the
        message data has changed.
        """

        # Modified for Prolink; was data[8] and data[9] for Balboa 
        self.time_hour = data[5]
        self.time_minute = data[6]

        # Byte 7 Bits 7,6,5 = currentWeek (actually day of week; 1 = Monday) 
        # Byte 7 Bits 4,3,2,1,0 = daysInMonth (actually day of month)
        self.dayOfWeek = (data[7] & 0xE0) >> 5
        self.dayOfMonth = (data[7] & 0x1F)

        # Byte 8 = currentMonth
        # Byte 9 = currentYear (since 2000)
        self.currentMonth = data[8]
        self.currentYear = data[9] + 2000

        # Byte 10 Bits 7,6 = Filter2Mode (0b00 = off)
        # Byte 10 Bits 5,4 = HeatModeState (0b01 = on-low?)
        # Byte 10 Bits 3,2,1,0 = SpaState 
        # (values of 1,2,8,9 or 10 get forced to -1) (0b0010 = 2)
        self.filter2Mode = (data[10] & 0xC0) >> 6
        self.heatModeState = (data[10] & 0x30) >> 4
        self.spaState = (data[10] & 0x0F)

        # TODO: why are heatmode and heatstate the same bits?
        # flag 2 is heatmode
        # Modified for Prolink; Balboa had no bit shift
        self.heatmode = (data[10] >> 4) & 0x03

        # flag 4 heating state, temp range
        # Modified for Prolink; Balboa was data[15]
        self.heatstate = (data[10] & 0x30) >> 4

        # Byte 11 = errorCode (0x00 = no error)
        self.errorCode = data[11]

        # Modified for Prolink; was data[7] for Balboa 
        curtemp = float(data[12])

        # Byte 13 = don't care? (0xFA)
        self.statusByte13 = data[13]

        # Modified for Prolink; was data[25] for Balboa 
        settemp = float(data[14])
        self.curtemp = curtemp / (2 if self.tempscale ==
                               self.TSCALE_C else 1) if curtemp != 255 else None
        self.settemp = settemp / (2 if self.tempscale == self.TSCALE_C else 1)

        # Byte 15 Bits 7,6 = Pump3State
        # Byte 15 Bits 5,4 = Pump2State (bit posn off by 1??)
        # Byte 15 Bits 3,2 = Pump1State 
        # Byte 15 Bits 1,0 read but not used
        self.pump3State = (data[15] & 0xC0) >> 6
        self.pump2State = (data[15] & 0x30) >> 4
        self.pump1State = (data[15] & 0x0C) >> 2
        self.pump0State = (data[15] & 0x03)

        # Modified for Prolink; does not have a temprange feature
        # self.temprange = (data[15] & 0x04) >> 2

        for i in range(0, 6):
            if not self.pump_array[i]:
                continue
            # 1-4 are in one byte, 5/6 are in another
            if i < 4:
                # Modified for Prolink; Balboa was data[16]
                self.pump_status[i] = (data[15] >> i*2) & 0x03
            # Modified for Prolink -- does not have pumps 5 or 6
            # else:
            #   self.pump_status[i] = (data[17] >> ((i - 4)*2)) & 0x03

        if self.circ_pump:
            # Modified for Prolink; not clear which pump is circ pump -- pump 0 maybe?
            # Answer: there is no circ pump on J-235. Pump 1 (Jets 1) runs at low speed
            # to circulate during filter cycles. Pump 0 does not exist so bits 0 & 1 of
            # data[15] will always be zero. HOWEVER, J-300 and J-400 series spas do
            # have a circulation pump so this is probably still needed.
            #
            # Balboa was data[18] == 0x02
            if data[15] & 0x03:
                self.circ_pump_status = 1
            else:
                self.circ_pump_status = 0

        # From Jacuzzi app code:
        # Byte 16 Bits 6,5 = IsSecondaryON
        # Byte 16 Bits 5,4 = IsPrimaryON (Bit posn off by 1??)
        # Byte 16 Bits 4,3 = IsBlowerON (Bit posn off by 1??_
        # Byte 16 Bits 2,1 = IsUVON
        #
        # But these bit positions seem to make more sense:
        # Byte 16 Bits 7,6 = IsSecondaryON
        # Byte 16 Bits 5,4 = IsPrimaryON (Bit posn off by 1??)
        # Byte 16 Bits 3,2 = IsBlowerON (Bit posn off by 1??)
        # Byte 16 Bits 1,0 = IsUVON
        # TODO: what are the real bit positions?
        #
        # All of these except isSecondaryOn will come on during
        # a filter cycle and also whenever pump 1 is turned on
        # manually. 
        self.isSecondaryOn = (data[16] & 0xC0) >> 6
        self.isPrimaryOn = (data[16] & 0x30) >> 4
        self.isBlowerOn = (data[16] & 0x0C) >> 2
        self.isUVOn = (data[16] & 0x03)

        # flag 3 is filter mode
        # Modified for Prolink IsPrimaryOn (bit 5,4 of byte 16)
        # Balboa was: self.filter_mode = (data[14] & 0x0c) >> 2
        #
        # It is possible that IsBlowerOn in Prolink is mislabeled
        # and actually is equivalent to filter_mode in Balboa.
        # If so then this should actually be:
        # self.filter_mode = (data[16] & 0x0C) >> 2
        self.filter_mode = (data[16] & 0x30) >> 4

        # It does not appear that any Jacuzzi hot tub has a blower
        # (at least at this time). This status is always on whenever
        # pump 1 is on.
        if self.blower:
            # Modified for Prolink; was data[18]. Same bits as isBlowerOn
            self.blower_status = (data[16] & 0x0c) >> 2

        # Byte 17 = don't care?
        # In Prolink byte17 seems to indicate that pump 1 is running
        # -- i.e. whenever pump 1 is on, byte 17 is 0x01. At all other
        # times it is 0x00. It is delayed by about 1 second with 
        # respect to changes in pump 1. It does transition oddly at the
        # end of a filter cycle though; turning off and back on
        # briefly. Perhaps this is a flow sensor signal?
        # UPDATE: Yes I believe it is the flow switch signal
        self.statusByte17 = data[17]

        # Modified for Prolink; was data[14] ; logic reversed??
        # TODO: resolve the logic reversal question
        # (12 hr only if both bits 2 & 1 are 0) (= 0x02)
        if data[18] & 0x06 == 0:
            self.timescale = self.TIMESCALE_12H
        else:
            self.timescale = self.TIMESCALE_24H

        # Modified for Prolink; was data[14] for Balboa (= 0x02)
        if data[18] & 0x01:
            self.tempscale = self.TSCALE_C
        else:
            self.tempscale = self.TSCALE_F

        # Byte 19 = don't care? (= 0x00)
        self.statusByte19 = data[19]

        for i in range(0, 2):
            if not self.light_array[i]:
                continue
            # Prolink light bits unclear; data[19] is unused??
            # Yes it appears data[19] does not hold light status.
            # Instead the light status is contained in message
            # type 0x23.
            self.light_status[i] = ((data[19] >> i*2) & 0x03) >> 1

        # Byte 20 Bits 5,4 = settingLock
        # Temperature lock status is bit 3 in the Jacuzzi J-235
        self.tempLock = (data[20] & 0x08) >> 3

        # Settings lock status is bit 2 in the Jacuzzi J-235
        self.settingsLock = (data[20] & 0x04) >> 2

        # Byte 20 Bits 3,2 = accessoriesLock
        # Accessories lock status is bit 1 in the Jacuzzi J-235
        self.accessoriesLock = (data[20] & 0x02) >> 1

        # Byte 20 Bits 1,0 = maintenanceLock (Bit posn error off by 1??)
        # Service lock status is bit 0 in the Jacuzzi J-235
        self.serviceLock = (data[20] & 0x01)

        # panelLock is balboa.py's name for settingsLock
        self.panelLock = self.settingsLock

        # Prolink does not support mister? data[20] has lock bits
        # if self.mister:
        #    self.mister_status = data[20] & 0x01
        # 
        # Yes it appears Jacuzzi does not have a mister feature on
        # any of its spas.

        # Modified for Prolink; does not have Aux channels?
        # It does not appear that any Jacuzzi hot tub has Aux 1 or 2
        # for i in range(0, 2):
        #     if not self.aux_array[i]:
        #         continue
        #     if i == 0:
        #         self.aux_status[i] = data[20] & 0x08
        #     else:
        #         self.aux_status[i] = data[20] & 0x10

        # Byte 21 = don't care? -- actually 2nd sensor of current water temp
        # Byte 22 = don't care?
        # Byte 23 = don't care?
        self.statusByte21 = data[21]
        self.statusByte22 = data[22]
        self.statusByte23 = data[23]

        # Byte 24 = CLEARRAYLSB
        # Byte 25 = CLEARRAYMSB
        # NOTE: MSB is actually LSB and LSB is MSB!
        self.clearrayTime = (data[24] * 256) + data[25]

        # Byte 26 = WATERLSB
        # Byte 27 = WATERMSB
        # NOTE: MSB is actually LSB and LSB is MSB!
        self.waterTime = (data[26] * 256) + data[27]

        if data[1] >= 30: # packet length including checksum byte
            # Byte 28 = OUTERFILTERLSB
            # Byte 29 = OUTERFILTERMSB
            # NOTE: MSB is actually LSB and LSB is MSB!
            self.outerFilterTime = (data[28] * 256) + data[29]
 
        if data[1] >= 32: # packet length including checksum byte
            # Byte 30 = INNERFILTERLSB
            # Byte 31 = INNERFILTERMSB
            # NOTE: MSB is actually LSB and LSB is MSB!
            self.innerFilterTime = (data[30] * 256) + data[31]

        if data[1] >= 33: # packet length including checksum byte
            # Byte 32 Bits 7,6,5,4 = WiFiState
            #  0 = SpaWifiState.Unknown
            #  1 = SpaWifiState.SoftAPmodeUnavailable
            #  2 = SpaWifiState.SoftAPmodeAvailable
            #  3 = SpaWifiState.InfrastructureMode
            #  4 = SpaWifiState.InfrastructureModeConnectedToNeworkNotCloud
            #  5 = SpaWifiState.InfrastructureModeConnectedToNeworkCloud
            #  14 = SpaWifiState.LINKINGTONETWORK
            #  15 = SpaWifiState.NOTCOMMUNICATINGTOSPA
            self.spaWifiState = (data[32] & 0xF0) >> 4

        if data[1] >= 37: # packet length including checksum byte
            # Byte 33 = don't care
            # Byte 34 = don't care
            # Byte 35 = don't care
            # Byte 36 = don't care
            self.statusByte33 = data[33]
            self.statusByte34 = data[34]
            self.statusByte35 = data[35]
            self.statusByte36 = data[36]

        # time.time() increments once per second
        self.lastupd = time.time()
        
        # balboa.py uses the class attribute self.new_data_cb to
        # support a user-provided asynchronous wait for new
        # data to be available before continuing. However balboa.py
        # initializes self.new_data_cb to None and never changes it
        # thereafter. Thus by default there will be no waiting for
        # new data before continuing. So for now anyway, we can
        # safely comment out this await.
        #
        # await self.int_new_data_cb()

    def parse_c4_status_update(self, data):
        """ Parse an encrypted status update from the spa.

        Encrypted status packets have a format different from both
        Jacuzzi and Balboa unencrypted status messages. 

        The spa spams these messages out at a very high rate of speed.
        Typical messages: 
           byte #: 000102030405 060708 09101112 13141516 17181920 21222324 25262728 29303132 33343536 37 3839
                   7e26ffafc41f 0d0000 080ab9f2 07006002 3818501d 61000117 080d2d08 b100006a 62383838 00 8a7e
DATE: 05/18/23 TIME:2:40PM, WS: 103, WT 102, Pump 1: OFF, Pump 2 OFF, LED: OFF, UV: ON
        Encrypted: 7e26ffafc4a2 aba6a7 a8ad0251 abadc8ad 90b122b6 d3b5b7a0 b8bc92bb 14bdbede e6818283 84 f07e
        Decrypted: 7e26ffafc4a2 0e0000 080ca0f2 07006602 3818881d 67000117 080d2008 a8000061 5e383838 00 ce7e
                   7e26ffafc48b 0e0000 080ca0f2 07006602 3818881d 67000117 080d2008 a8000061 5e383838 00 bb7e
                   7e26ffafc4e5 0e0000 080ca0f2 07006602 3818881d 67000117 080d2108 a8000061 5e383838 00 907e
               TIME:2:41PM, WS: 103, WT 102, Pump 1: ON, Pump 2 OFF, LED: OFF, UV: ON
                   7e26ffafc43c 0e4000 081ca0f2 07406602 3818881d 67000117 080d2108 a8000061 5e183838 00 757e
                   7e26ffafc46f 0e4000 081ca0f2 07406602 3818881d 67000117 080d2208 a8000061 5e183838 00 a27e
               TIME:2:41PM, WS: 103, WT 101, Pump 1: OFF, Pump 2 ON, LED: OFF, UV: ON
                   7e26ffafc4c0 0e0004 080ca0f2 07006602 3818881d 67000117 080d2208 a8000061 5e383838 00 697e
                   7e26ffafc484 0e0004 080ca0f2 07006602 3818881d 67000117 080d2208 a8000061 5e383838 00 0c7e
               TIME:2:42PM,WS: 103, WT 101, Pump 1: ON, Pump 2 ON, LED: OFF, UV: ON
                   7e26ffafc4d5 0e4004 081ca0f2 07406602 3818881d 67000117 080d2208 a8000061 5e183838 00 237e
                   7e26ffafc4b2 0e4004 081ca0f2 07406602 3818881d 67000117 080d2208 a8000061 5e183838 00 eb7e
               TIME:2:43PM,WS: 103, WT 101 (maybe 102), Pump 1: OFF, Pump 2 OFF, LED: ON - Changing colors, UV: ON
                   7e26ffafc44c 0e0000 080ca0f2 07006602 3818881d 67000117 080d2308 a8000061 5e383838 00 f17e
                   7e26ffafc4ee 0e4000 080ca0f2 07406602 3818881d 67000117 080d2308 a8000061 5e183838 00 1a7e
               TIME:2:43PM,WS: 103, WT 101 (maybe 102), Pump 1: OFF, Pump 2 OFF, LED: ON - BLUE, UV: ON
                   7e26ffafc4d1 0e4000 080ca0f2 07406602 3818881d 67000117 080d2408 a8000061 5e183838 00 bd7e
        """
 
        # Modified for Prolink; was data[8] and data[9] for Balboa 
        self.time_hour = data[6]
        # Byte 27 = CurrentTimeMinute (probably only bits 5-0) (0x19)
        self.time_minute = data[27] & 0x3F

        # Byte 7 Bits 7,6,5 = currentWeek (actually day of week; 1 = Monday) 
        # Byte 7 Bits 4,3,2,1,0 = daysInMonth (actually day of month)
        # self.dayOfWeek = (data[7] & 0xE0) >> 5
        self.dayOfWeek = (data[20] & 0x07)        # Not sure this is correct
        self.dayOfMonth = (data[19] & 0xF8) >> 3

        # Have not found this yet
        # Byte 8 = currentMonth
        # self.currentMonth = (data[20] & 0x7)

        # Byte 24 = currentYear (since 2000)
        self.currentYear = data[24] + 2000

        # Byte 10 Bits 7,6 = Filter2Mode (0b00 = off)
        # Byte 10 Bits 5,4 = HeatModeState (0b01 = on-low?)
        # Byte 10 Bits 3,2,1,0 = SpaState 
        # (values of 1,2,8,9 or 10 get forced to -1) (0b0010 = 2)
        # self.filter2Mode = (data[10] & 0xC0) >> 6
        # self.heatModeState = (data[10] & 0x30) >> 4
        # self.spaState = (data[10] & 0x0F)

        # TODO: why are heatmode and heatstate the same bits?
        # flag 2 is heatmode
        # Modified for encrypted; Balboa had no bit shift
        # Byte 18 = heatMode (0x18)
        self.heatmode = (data[18] >> 4) & 0x03

        # flag 4 heating state, temp range
        # Modified for encrypted; Balboa was data[15]
        # Byte 26 = Bit 6 = heaterOn (0x0c, 0x0d, 0x8d)
        self.heatstate = (data[26] & 0x40) >> 6

        # Byte 11 = errorCode (0x00 = no error)
        # self.errorCode = data[11]

        # Modified for Prolink; was data[7] for Balboa 
        curtemp = float(data[15])

        # Byte 13 = don't care? (0xFA)
        # self.statusByte13 = data[13]

        # Modified for Prolink; was data[25] for Balboa 
        settemp = float(data[21])
        self.curtemp = curtemp / (2 if self.tempscale ==
                               self.TSCALE_C else 1) if curtemp != 255 else None
        self.settemp = settemp / (2 if self.tempscale == self.TSCALE_C else 1)

        # Byte 15 Bits 7,6 = Pump3State
        # Byte 15 Bits 5,4 = Pump2State (bit posn off by 1??)
        # Byte 15 Bits 3,2 = Pump1State 
        # Byte 15 Bits 1,0 read but not used
        # 
        # From Pedro and HyperActiveJ's work:
        # HyperActiveJ's pump0 = Pedro's pump1
        # HyperActiveJ's pump1 = Pedro's pump2?? - yes, but HyperActiveJ is not consistent.
        # Pump0 = circ pump ?? (if present)
        #
        # Byte 8 Bits 7,6 = pump0State (circ pump?) (0b00)
        # Byte 8 Bits 3,2 = pump2State (blower?) (0b00, 0x00,0x04)
        self.pump2State = (data[8] & 0x0c) >> 2
        self.pump0State = (data[8] & 0xc0) >> 6

        # Byte 10 Bit 7 = ManualCirc (0b0)
        # Byte 10 Bit 6 = AutoCirc (0b0)
        # Byte 10 Bits 5,4 = pump1State (0b00, 0x0c, 0x0d, 0x1d, 0x0e, 0x1e)
        self.pump1State = (data[10] & 0x30) >> 4

        # Modified for Prolink; does not have a temprange feature
        # self.temprange = (data[15] & 0x04) >> 2

        # From Pedro and HyperActiveJ's work:
        # TODO: This is a hack, just to see if it works
        for i in range(0, 6):
            if not self.pump_array[i]:
                continue
            if i == 0:
                self.pump_status[i] = self.pump0State
            elif i == 1:
                self.pump_status[i] = self.pump1State
            elif i == 2:
                self.pump_status[i] = self.pump2State
            else:
                continue

            # Modified for Prolink -- does not have pumps 5 or 6
            # else:
            #   self.pump_status[i] = (data[17] >> ((i - 4)*2)) & 0x03

        # if self.circ_pump:
            # Modified for Prolink; not clear which pump is circ pump -- pump 0 maybe?
            # Answer: there is no circ pump on J-235. Pump 1 (Jets 1) runs at low speed
            # to circulate during filter cycles. Pump 0 does not exist so bits 0 & 1 of
            # data[15] will always be zero. HOWEVER, J-300 and J-400 series spas do
            # have a circulation pump so this is probably still needed.
            #
            # Balboa was data[18] == 0x02
            # if data[15] & 0x03:
            #     self.circ_pump_status = 1
            # else:
            #     self.circ_pump_status = 0

        # From Jacuzzi app code:
        # Byte 16 Bits 6,5 = IsSecondaryON
        # Byte 16 Bits 5,4 = IsPrimaryON (Bit posn off by 1??)
        # Byte 16 Bits 4,3 = IsBlowerON (Bit posn off by 1??)

        # But these bit positions seem to make more sense:
        # Byte 16 Bits 7,6 = IsSecondaryON
        # Byte 16 Bits 5,4 = IsPrimaryON (Bit posn off by 1??)
        # Byte 16 Bits 3,2 = IsBlowerON (Bit posn off by 1??)
        # Byte 16 Bits 1,0 = IsUVON
        # TODO: what are the real bit positions?
        #
        # All of these except isSecondaryOn will come on during
        # a filter cycle and also whenever pump 1 is turned on
        # manually. 
        # self.isSecondaryOn = (data[16] & 0xC0) >> 6
        # self.isPrimaryOn = (data[16] & 0x30) >> 4
        # self.isBlowerOn = (data[16] & 0x0C) >> 2

        # Byte 16 Bits 2,1 = IsUVON
        # Byte 7 Bit 6 = UV On (0b0, 0x00, 0x40, 0x60)
        self.isUVOn = (data[7] & 0xc0) >> 6

        # flag 3 is filter mode
        # Modified for Prolink IsPrimaryOn (bit 5,4 of byte 16)
        # Balboa was: self.filter_mode = (data[14] & 0x0c) >> 2
        #
        # It is possible that IsBlowerOn in Prolink is mislabeled
        # and actually is equivalent to filter_mode in Balboa.
        # If so then this should actually be:
        # self.filter_mode = (data[16] & 0x0C) >> 2
        # self.filter_mode = (data[16] & 0x30) >> 4

        # It does not appear that any Jacuzzi hot tub has a blower
        # (at least at this time). This status is always on whenever
        # pump 1 is on.
        # if self.blower:
            # Modified for Prolink; was data[18]. Same bits as isBlowerOn
            # self.blower_status = (data[16] & 0x0c) >> 2

        # Byte 17 = don't care?
        # In Prolink byte17 seems to indicate that pump 1 is running
        # -- i.e. whenever pump 1 is on, byte 17 is 0x01. At all other
        # times it is 0x00. It is delayed by about 1 second with 
        # respect to changes in pump 1. It does transition oddly at the
        # end of a filter cycle though; turning off and back on
        # briefly. Perhaps this is a flow sensor signal?
        # UPDATE: Yes I believe it is the flow switch signal
        # self.statusByte17 = data[17]

        # Modified for Prolink; was data[14] ; logic reversed??
        # TODO: resolve the logic reversal question
        # (12 hr only if both bits 2 & 1 are 0) (= 0x02)
        # if data[18] & 0x06 == 0:
            # self.timescale = self.TIMESCALE_12H
        # else:
            # self.timescale = self.TIMESCALE_24H

        # Modified for Prolink; was data[14] for Balboa (= 0x02)
        # if data[18] & 0x01:
            # self.tempscale = self.TSCALE_C
        # else:
            # self.tempscale = self.TSCALE_F

        # Byte 19 = don't care? (= 0x00)
        # self.statusByte19 = data[19]

        # for i in range(0, 2):
            # if not self.light_array[i]:
                # continue
            # Prolink light bits unclear; data[19] is unused??
            # Yes it appears data[19] does not hold light status.
            # Instead the light status is contained in message
            # type 0x23.
            # self.light_status[i] = ((data[19] >> i*2) & 0x03) >> 1

        # Byte 20 Bits 5,4 = settingLock
        # Byte 20 Bits 3,2 = accessLock
        # Byte 20 Bits 1,0 = maintenanceLock (Bit posn error off by 1??)
        # self.settingLock = (data[20] & 0x30) >> 4
        # self.accessLock = (data[20] & 0x0C) >> 2
        # self.serviceLock = (data[20] & 0x03)

        # Prolink does not support mister? data[20] has lock bits
        # if self.mister:
        #    self.mister_status = data[20] & 0x01
        # 
        # Yes it appears Jacuzzi does not have a mister feature on
        # any of its spas.

        # Modified for Prolink; does not have Aux channels?
        # It does not appear that any Jacuzzi hot tub has Aux 1 or 2
        # for i in range(0, 2):
        #     if not self.aux_array[i]:
        #         continue
        #     if i == 0:
        #         self.aux_status[i] = data[20] & 0x08
        #     else:
        #         self.aux_status[i] = data[20] & 0x10

        # Byte 21 = don't care? -- actually 2nd sensor of current water temp
        # Byte 22 = don't care?
        # Byte 23 = don't care?
        # self.statusByte21 = data[21]
        # self.statusByte22 = data[22]
        # self.statusByte23 = data[23]

        # Byte 24 = CLEARRAYLSB
        # Byte 25 = CLEARRAYMSB
        # NOTE: MSB is actually LSB and LSB is MSB!
        # self.clearrayTime = (data[24] * 256) + data[25]

        # Byte 26 = WATERLSB
        # Byte 27 = WATERMSB
        # NOTE: MSB is actually LSB and LSB is MSB!
        # self.waterTime = (data[26] * 256) + data[27]

        # if data[1] >= 30: # packet length including checksum byte
            # Byte 28 = OUTERFILTERLSB
            # Byte 29 = OUTERFILTERMSB
            # NOTE: MSB is actually LSB and LSB is MSB!
            # self.outerFilterTime = (data[28] * 256) + data[29]
 
        # if data[1] >= 32: # packet length including checksum byte
            # Byte 30 = INNERFILTERLSB
            # Byte 31 = INNERFILTERMSB
            # NOTE: MSB is actually LSB and LSB is MSB!
            # self.innerFilterTime = (data[30] * 256) + data[31]

        # if data[1] >= 33: # packet length including checksum byte
            # Byte 32 Bits 7,6,5,4 = WiFiState
            #  0 = SpaWifiState.Unknown
            #  1 = SpaWifiState.SoftAPmodeUnavailable
            #  2 = SpaWifiState.SoftAPmodeAvailable
            #  3 = SpaWifiState.InfrastructureMode
            #  4 = SpaWifiState.InfrastructureModeConnectedToNeworkNotCloud
            #  5 = SpaWifiState.InfrastructureModeConnectedToNeworkCloud
            #  14 = SpaWifiState.LINKINGTONETWORK
            #  15 = SpaWifiState.NOTCOMMUNICATINGTOSPA
            # self.spaWifiState = (data[32] & 0xF0) >> 4

        # if data[1] >= 37: # packet length including checksum byte
            # Byte 33 = don't care
            # Byte 34 = don't care
            # Byte 35 = don't care
            # Byte 36 = don't care
            # self.statusByte33 = data[33]
            # self.statusByte34 = data[34]
            # self.statusByte35 = data[35]
            # self.statusByte36 = data[36]

        # time.time() increments once per second
        self.lastupd = time.time()
 
    def parse_system_information(self, data):
        """ Overrides parent method to handle the dofferemces in Jaccuzi 
        system information message packets vs those in Balboa systems.

        Emulating the Prolink app behavior -- this just reads byte 7 of
        the message packet and if the value there is less than 6, it 
        sets isOldVersion = true, or false otherwise.
        """

        self.sysInfoByte5 = data[5]
        self.sysInfoByte6 = data[6]
        if (data[7] < 6):
            self.isOldVersion = True
        else:
            self.isOldVersion = False

    def parse_secondary_filter(self, data):
        """ Decodes the Jaccuzi-specifc Secondary Filter Cycle
        message packet. 
        """

        # According to the Prolink app this message has 3 data bytes but
        # only the first (data[5]) contains the current Secondary Filter
        # Cycle setting. Allowed values are 0, 1 or 2 indicating
        # "Holiday" "Light" or "Heavy" respectively.
        #
        # The value of second and 3rd data bytes always seems to be 0x0A 
        self.SecondaryFilterCycle = data[5]
        self.secFilterByte6 = data[6]
        self.secFilterByte7 = data[7]

    def parse_primary_filtration(self, data): 
        """Parse a Jacuzzi Primary Filtration message packet. """

        # This just reads bytes 5 and 6 of the message packet and
        # saves them. Oddly though, I have not found any code in
        # the Prolink app that handles these bytes. Yet the app
        # does display the primary filtration start time and duration.
        # It also seems to let you change the number of cycles per
        # day, which may be the purpose of data[7].
        #
        # The display of primary filtration in the Prolink app may
        # come from reading the panel update status message instead.
        startHour = data[5]
        durationHours = data[6]
        if (startHour >= 0):
            self.filter1StartHour = startHour 
        if (durationHours >= 0):
            self.filter1DurationHours = durationHours

        # Manual says 1,2,3,4, or 8 are allowed values for frequency
        filter1Freq = data[7]
        if (filter1Freq > 0 and filter1Freq <= 4) or filter1Freq == 8:
            self.filter1Freq = filter1Freq

    def parse_setup_parameters(self, data): 
        """Parse a Jacuzzi Setup Parameters message packet. """

        # This message type is defined in the Prolink app but it does
        # not seem to be used in the app.  Might be a leftover from
        # Balboa code that was not needed or implemented.  This message
        # type in Balboa systems seems to handle features (such as high
        # and low temperature ranges) that Jacuzzi does not support.
        #
        # There is a Panel Request Type of the same name, so presumably
        # the app can request setup parameters from the spa controller.
        # But there does not seem to be any code in Prolink to parse this
        # message type if it is received from the spa controller. And yet
        # the Jacuzzi spa controller does return this message type.
        #
        # In the actual J-235 hot tub, sending a Panel Request message
        # (type 0x19 with payload1 = 0x04, payload2 = 0x00) to the spa
        # controller returns this message with type value 0x1E which is
        # not defined in either Balboa systems or the Prolink app. The
        # two data bytes in the returned message packet (Byte 5 and 6)
        # always seem to be 0x18 and 0x01.
        self.setupByte5 = data[5]
        self.setupByte6 = data[6]

    def parse_pump_state(self, data):
        """ Parses a Jacuzzi "Pump State" message. """
  
        # This just reads the 6 upper bits of Byte 11 of the message
        # packet, counts the number of pumps present, and saves that
        # to the spa object's attributes. Oddly though, in the Prolink
        # app, nothing is ever done with the results.
        self.pumpStateByte5 = data[5]
        self.pumpStateByte6 = data[6]
        self.pumpStateByte7 = data[7]
        self.pumpStateByte8 = data[8]
        self.pumpStateByte9 = data[9]
        self.pumpStateByte10 = data[10]

        pump3bits = (data[11] & 0xC0) >> 6
        pump2bits = (data[11] & 0x30) >> 4
        pump1bits = (data[11] & 0x0C) >> 2
        pump0bits = (data[11] & 0x03)
        pumpcount = 0
        if pump3bits != 0:
            pumpcount += 1
        if pump2bits != 0:
            pumpcount += 1
        if pump1bits != 0:
            pumpcount += 1
        if pump0bits != 0:
            pumpcount += 1
        self.numberOfPumps = pumpcount
        self.pump3State = pump3bits
        self.pump2State = pump2bits
        self.pump1State = pump1bits
        self.pump0State = pump0bits

        self.pumpStateByte12 = data[12]
        self.pumpStateByte13 = data[13]
        self.pumpStateByte14 = data[14]
        self.pumpStateByte15 = data[15]
        self.pumpStateByte16 = data[16]
        self.pumpStateByte17 = data[17]
        # self.log.debug('Pump3: {0} Pump2: {1} Pump1: {2}; Total = {3}'.format(pump3bits, pump2bits, pump1bits, pumpcount))

    def parse_light_status_update(self, data): 
        """Parse a Jacuzzi Light status update message packet. """

        # This message type is not defined in the Prolink app 
        # or balboa.py but the Jacuzzi J-235 spa does broadcast this
        # at regular intervals, much like the PLNK_STATUS_UPDATE
        # message. It contains the current state of the LED lights.
        #
        # Byte 5 = Color code
        # Byte 7 = Brightness level
        # Byte 8 = Red Level
        # Byte 9 = Green Level
        # Byte 10 = Blue Level
        self.lightMode = data[5]
        self.lightBrightness = data[7]
        self.lightR = data[8]
        self.lightG = data[9]
        self.lightB = data[10]
        self.log.info('Light status: L: {0} R: {1} G: {2} B: {3}'.format(
                      self.lightBrightness, 
                      self.lightR, 
                      self.lightG, 
                      self.lightB))

    def parse_ca_light_status_update(self, data): 
        """ Parse an encrypted Jacuzzi Light status update message packet.

        Typical encrypted CA packet:
        byte #:    000102030405 060708 09101112 13141516 17181920 21222324 25262728 29303132 33 3435
        encrypted: 7e22ffafca83 3fc380 cd33cf8c cbc8cbcb d5d4d7d6 d1d0d3d2 dddcdfdf d9d8dbda e5 b27e
        decrypted: 7e22ffafca83 ff0042 00ff0042 02000001 00000000 00000000 00000001 00000000 00 557e (LEDs on solid blue)
                   7e22ffafca70 ff0042 00ff0042 02000001 00000000 00000000 00000001 00000000 00 357e (LEDs on solid blue)
                   7e22ffafca43 000000 00000000 00000000 00000000 00000000 00000001 00000000 00 b87e (All LEDs off)
                   7e22ffafca58 ff0042 00220042 80000001 00000000 00dc0002 00000001 00000000 00 d77e (Changing colors)
                   7e22ffafcae2 ff0042 00000042 80000001 00290000 00d60002 00000001 00000000 00 887e (Changing colors)
                   7e22ffafca79 ff0042 00000042 80000001 00750000 00890002 00000001 00000000 00 b97e (Changing colors)
                   7e22ffafcacd ff0042 00000042 80000001 00c20000 003c0002 00000001 00000000 00 b27e (Changing colors)
                   7e22ffafca24 ff0042 000f0042 80000001 00ef0000 00000002 00000001 00000000 00 5d7e (Changing colors)
                   7e22ffafca91 ff0042 005c0042 80000001 00a20000 00000002 00000001 00000000 00 0f7e (Changing colors)
        """

        # This message type is not defined in the Prolink app 
        # or balboa.py but "encrypted" spa controllers do broadcast this
        # at regular intervals, much like the PLNK_STATUS_UPDATE
        # message. It contains the current state of the LED lights.
        # 
        # The byte positions differ from non-encrypted LED status message
        # (type 0x23), and it adds a field for light cycle time (fast
        # or slow).
        #
        # Byte 6 = Brightness Level
        # Byte 10 = Blue Level
        # Byte 13 = Light Mode
        # Byte 18 = Green Level
        # Byte 22 = Red Level
        # Byte 24 = Light Cycle Time

        self.lightMode = data[13]
        self.lightBrightness = data[6]
        self.lightR = data[22]
        self.lightG = data[18]
        self.lightB = data[10]
        self.lightCycleTime = data[24]
        self.log.info('Light status: L: {0} R: {1} G: {2} B: {3}'.format(
                      self.lightBrightness, 
                      self.lightR, 
                      self.lightG, 
                      self.lightB))

    async def read_one_message(self):
        """ Overrides parent method to update self.connection_state
        and add debug logging.
        """
        msg = await super().read_one_message()
        if (msg is not None and 
            self.connection_state is not ConnectionStates.Connected
        ):
            self.connection_state = ConnectionStates.Connected

        self.log.debug('Received message: {}'.format(msg.hex())
            if msg is not None else 'Read failed'
        )
        return msg

    def find_balboa_mtype(self, data):
        """ Overrides parent method to add Jacuzzi-specific message types.

        data is a byte array of the complete message packet including
        start and end flag bytes.

        Returns the enumerated constant that identifies the packet's
        message type field. Returns None if data is None, or if the
        type field value is not recognized.
        """

        # Some Jacuzzi message types have the same value as some other
        # message type in Balboa systems. So we need to check for
        # Jacuzzi type values first. Only if not found should we check
        # for Balboa types.
        #
        # Balboa BMTR_STATUS_UPDATE type value is 0x13 instead of 0x16
        # Balboa BMTR_FILTER_INFO_RESP type value is 0x23 not 0x27
        # (In Balboa systems BMTS_SET_TSCALE = 0x27)
        # Balboa BMTS_PANEL_REQ type value is 0x22 instead of 0x19

        if data is None or len(data) < 5:
            mtype = None
        elif data[4] == 0x16:
            mtype = PLNK_STATUS_UPDATE
        elif data[4] == 0x27:
            mtype = PLNK_FILTER_INFO_RESP
        elif data[4] == 0x19:
            mtype = PLNK_PANEL_REQ
        elif data[4] == 0x1C:
            mtype = PLNK_SECONDARY_FILTER_RESP
        elif data[4] == 0x1B:
            mtype = PLNK_PRIMARY_FILTER_RESP
        elif data[4] == 0x1D:
            mtype = PLNK_PUMP_STATE_RESP
        elif data[4] == 0x1E:
            mtype = PLNK_SETUP_PARAMS_RESP
        elif data[4] == 0x23:
            mtype = PLNK_LIGHTS_UPDATE

        # Support encrypted packet types
        elif data[4] == 0xC4:
            mtype = PLNK_C4_STATUS_UPDATE
        elif data[4] == 0xCA:
            mtype = PLNK_CA_LIGHTS_UPDATE

        else:
            mtype = super().find_balboa_mtype(data)
        return mtype 

    def process_message(self, data):
        """ Identify, parse and decode a known message
            
        data is a byte array that should contain the entire message
        including start and end flag bytes.

        Returns the enumerated message type of the message,
        or None if nothing changed. Also returns None and logs an
        error message if data is None.
        """

        if data is None:
            self.log.error(f"data is None in process_message()")
            return None

        # Decrypt the packet if it is encrypted
        data = self.decrypt(data)

        mtype = self.find_balboa_mtype(data)
        if mtype is None:
            self.log.debug("Unknown msg type 0x{:02X} in process_message()".format(data[4]))
 
        elif not self.has_changed(data):
            mtype = None
        elif mtype == BMTR_MOD_IDENT_RESP:
            self.parse_module_identification(data)
        # Modified for Prolink; was BMTR_STATUS_UPDATE
        elif mtype == PLNK_STATUS_UPDATE:
            self.parse_status_update(data)
        elif mtype == BMTR_DEVICE_CONFIG_RESP:
            self.parse_device_configuration(data)
        elif mtype == BMTR_SYS_INFO_RESP:
            self.parse_system_information(data)
        elif mtype == BMTR_SETUP_PARAMS_RESP:
            self.parse_setup_parameters(data)
        # Modified for Prolink; was BMTR_FILTER_INFO_RESP
        elif mtype == PLNK_FILTER_INFO_RESP:
            self.parse_filter_cycle_info(data)
        # Modified for Prolink; added the following Prolink-specific msg types
        elif mtype == PLNK_SECONDARY_FILTER_RESP:
            self.parse_secondary_filter(data)
        elif mtype == PLNK_PRIMARY_FILTER_RESP:
            self.parse_primary_filtration(data)
        elif mtype == PLNK_PUMP_STATE_RESP:
            self.parse_pump_state(data)
        elif mtype == PLNK_SETUP_PARAMS_RESP:
            self.parse_setup_parameters(data)
        elif mtype == PLNK_LIGHTS_UPDATE:
            self.parse_light_status_update(data)

        # Support encrypted message types
        elif mtype == PLNK_C4_STATUS_UPDATE:
            self.parse_c4_status_update(data)
        elif mtype == PLNK_CA_LIGHTS_UPDATE:
            self.parse_ca_light_status_update(data)

        else:
            self.log.error("Unhandled msg type 0x{0:02X} ({0}) in process_message()".format(data[4]))
        return mtype

    async def listen_for_mtype(self, msg_type, msg_limit = 5):
        """ Listens until a specific message type is received
        or too many messages have been received
        """

        for i in range(0, msg_limit):
            mtype = None
            msg = await self.read_one_message()
            if msg is not None:
                mtype = self.process_message(msg)
            if mtype == msg_type:
                break
        return mtype

    async def check_connection_status(self):
        """ Overrides the parent method to connect and reconnect as needed
        for Jacuzzi spas. This should run as a coroutine or task concurrently
        with other asynchronous coroutines.
        """

        timeout = 90 # Seconds
        while True:
            # self.connect() will set self.connected to True when
            # asyncio.open_connection() succeeds.
            #
            # self.read_one_message() will set self.connected to False
            # on any socket read error.

            if not self.connected:
                self.log.info("Connecting...")
                await self.connect()
                self.connection_state = ConnectionStates.Connecting

                # if connect() succeeded then send a primary filter request
                if self.connected:
                    await self.send_filter1_cycle_req()

            else:
                # We are connected. New updates typically come in every
                # second or so. So if we haven't received one recently,
                # send the spa a message to see if it will respond.

                if time.time() > self.lastupd + timeout:
                    self.connection_state = ConnectionStates.Disconnected
                    self.log.info("Requesting module ID.")
                    await self.send_mod_ident_req()

                    self.lastupd = time.time()

                    # Wait a bit before checking again. The spa seems to need
                    # more time to recover from a module_ident_req() command.
                    # await asyncio.sleep(10)
                    continue

            # Wait a bit before checking again.
            await asyncio.sleep(1)

    async def listen(self):
        """ Overrides parent method to parse Jacuzzi-specific msg types

        This is an infinite loop to read and process incoming messages.
        It checks periodically to see if we are connected to the spa,
        When connected it reads and processes one message packet at a
        time, sleeping briefly between packets.
        """

        while True:
            if not self.connected:
                # sleep and hope the checker fixes us
                await asyncio.sleep(5)
                continue
            data = await self.read_one_message()
            if data is None:
                self.connection_state = ConnectionStates.Disconnected
                await asyncio.sleep(1)
                continue
            self.process_message(data)
            await asyncio.sleep(0.1)

    async def spa_configured(self):
        # TODO: make this override actually work for Jacuzzi spas
        # Jacuzzi spa must be manually configured so make this always true
        # for now. The parent method will never work for Jacuzzi spas since
        # panel request types are different between Balboa and Jacuzzi
        # systems. Also I have not been able to get the J-235 to respond
        # with a config data message packet. Doesn't seem like Jacuzzi supports
        # this method of configuration.
        return True 

    async def listen_until_configured(self, maxiter=20):
        # TODO: remove this config override if not relevant to Jacuzzi spas
        return True
   
    # Additional accessors not provided by the parent class
    # TODO: remove any accessors that are not relevant to Jacuzzi spas

    def get_connection_state_text(self):
        return self.connection_state.name

    def get_spatime_text(self):
        return "Spa Time: {0:02d}:{1:02d} {2}".format(
            self.time_hour,
            self.time_minute,
            self.get_timescale(True)
        )

    def get_day(self):
        return self.dayOfMonth
        
    def get_month(self):    
        return self.currentMonth 
        
    def get_year(self):  
        return self.currentYear

    def get_spadate_text(self):
        return "Spa Date: {0}/{1}/{2}".format(
            self.get_month(), 
            self.get_day(),
            self.get_year()
        )
        
    def get_curtemp_text(self):  
        return ("Water Temp: {0}".format(self.get_curtemp()))

    def get_2ndtemp_text(self):  
        return ("2nd Temp: {0}".format(self.statusByte21)) 

    def get_settemp_text(self):  
        return ("Setpoint Temp: {0}".format(self.get_settemp())) 

    def change_settemp(self, newtemp):
        self.send_temp_change(newtemp)

    def get_temp2(self):  
        return self.temp2 
        
    def get_manualCirc(self):  
        return self.manualCirc 
        
    def get_autoCirc(self):  
        return self.autoCirc
        
    def get_unknownCirc(self):  
        return self.unknownCirc
        
    def get_heatstate_text(self):  
        return "Heater: {0}".format(self.get_heatstate(True))

    def get_heatState2(self):  
        return self.heatState2

    def get_displayText(self):  
        return self.displayText 
        
    def get_heatMode(self):  
        return self.heatMode 
        
    def get_UnknownField3(self):  
        return self.UnknownField3
        
    def get_UnknownField9(self):  
        return self.UnknownField9 
        
    # From balboa.py -- same as settingsLock
    def get_panelLock(self):  
        return self.panelLock 

    def get_settingsLock(self):  
        return self.settingsLock 

    def get_accessoriesLock(self):  
        return self.accessoriesLock 

    def get_serviceLock(self):  
        return self.serviceLock 
        
    def get_lightBrightness(self):  
        return self.lightBrightness
        
    def get_lightMode(self):  
        return self.lightMode
        
    def get_lightR(self):  
        return self.lightR
        
    def get_lightG(self):  
        return self.lightG
        
    def get_lightB(self):  
        return self.lightB 

