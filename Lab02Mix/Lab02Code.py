#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 02
#
# Basics of Mix networks and Traffic Analysis
#
# Run the tests through:
# $ py.test -v test_file_name.py

#####################################################
# TASK 1 -- Ensure petlib is installed on the System
#           and also pytest. Ensure the Lab Code can 
#           be imported.

###########################
# Group Members: TODO
###########################


from collections import namedtuple
from hashlib import sha512
from struct import pack, unpack
from binascii import hexlify

def aes_ctr_enc_dec(key, iv, input):
    """ A helper function that implements AES Counter (CTR) Mode encryption and decryption. 
    Expects a key (16 byte), and IV (16 bytes) and an input plaintext / ciphertext.

    If it is not obvious convince yourself that CTR encryption and decryption are in 
    fact the same operations.
    """
    
    aes = Cipher("AES-128-CTR") 

    enc = aes.enc(key, iv)
    output = enc.update(input)
    output += enc.finalize()

    return output

#####################################################
# TASK 2 -- Build a simple 1-hop mix client.
#
#


## This is the type of messages destined for the one-hop mix
OneHopMixMessage = namedtuple('OneHopMixMessage', ['ec_public_key', 
                                                   'hmac', 
                                                   'address', 
                                                   'message'])

from petlib.ec import EcGroup
from petlib.hmac import Hmac, secure_compare
from petlib.cipher import Cipher

def mix_server_one_hop(private_key, message_list):
    """ Implements the decoding for a simple one-hop mix. 

        Each message is decoded in turn:
        - A shared key is derived from the message public key and the mix private_key.
        - the hmac is checked against all encrypted parts of the message
        - the address and message are decrypted, decoded and returned

    """
    G = EcGroup()

    out_queue = []

    # Process all messages
    for msg in message_list:

        ## Check elements and lengths
        if not G.check_point(msg.ec_public_key) or \
               not len(msg.hmac) == 20 or \
               not len(msg.address) == 258 or \
               not len(msg.message) == 1002:
           raise Exception("Malformed input message")

        ## First get a shared key
        shared_element = private_key * msg.ec_public_key
        key_material = sha512(shared_element.export()).digest()

        # Use different parts of the shared key for different operations
        hmac_key = key_material[:16]
        address_key = key_material[16:32]
        message_key = key_material[32:48]

        ## Check the HMAC
        h = Hmac(b"sha512", hmac_key)        
        h.update(msg.address)
        h.update(msg.message)
        expected_mac = h.digest()

        if not secure_compare(msg.hmac, expected_mac[:20]):
            raise Exception("HMAC check failure")

        ## Decrypt the address and the message
        iv = b"\x00"*16

        address_plaintext = aes_ctr_enc_dec(address_key, iv, msg.address)
        message_plaintext = aes_ctr_enc_dec(message_key, iv, msg.message)

        # Decode the address and message
        address_len, address_full = unpack("!H256s", address_plaintext)
        message_len, message_full = unpack("!H1000s", message_plaintext)

        output = (address_full[:address_len], message_full[:message_len])
        out_queue += [output]

    return sorted(out_queue)
        
        
def mix_client_one_hop(public_key, address, message):
    """
    Encode a message to travel through a single mix with a set public key. 
    The maximum size of the final address and the message are 256 bytes and 1000 bytes respectively.
    Returns an 'OneHopMixMessage' with four parts: a public key, an hmac (20 bytes),
    an address ciphertext (256 + 2 bytes) and a message ciphertext (1002 bytes). 
    """
    G = EcGroup()
    assert G.check_point(public_key)
    assert isinstance(address, bytes) and len(address) <= 256
    assert isinstance(message, bytes) and len(message) <= 1000

    # Encode the address and message
    # Use those as the payload for encryption
    address_plaintext = pack("!H256s", len(address), address)
    message_plaintext = pack("!H1000s", len(message), message)

    ## Generate a fresh public key
    private_key = G.order().random()
    client_public_key  = private_key * G.generator()

    ## ADD CODE HERE
    
    ## First get a shared key
    shared_element = private_key * public_key
    key_material = sha512(shared_element.export()).digest()

    # Use different parts of the shared key for different operations
    hmac_key = key_material[:16]
    address_key = key_material[16:32]
    message_key = key_material[32:48]


    ## Encrypt the address and the message
    iv = b"\x00"*16

    address_cipher = aes_ctr_enc_dec(address_key, iv, address_plaintext)
    message_cipher = aes_ctr_enc_dec(message_key, iv, message_plaintext)  
    
    ## Check the HMAC
    h = Hmac(b"sha512", hmac_key)        
    h.update(address_cipher)
    h.update(message_cipher)
    expected_mac = h.digest()[:20]

    return OneHopMixMessage(client_public_key, expected_mac, address_cipher, message_cipher)

    

#####################################################
# TASK 3 -- Build a n-hop mix client.
#           Mixes are in a fixed cascade.
#

from petlib.ec import Bn

# This is the type of messages destined for the n-hop mix
NHopMixMessage = namedtuple('NHopMixMessage', ['ec_public_key', 
                                                   'hmacs', 
                                                   'address', 
                                                   'message'])


def mix_server_n_hop(private_key, message_list, final=False):
    """ Decodes a NHopMixMessage message and outputs either messages destined
    to the next mix or a list of tuples (address, message) (if final=True) to be 
    sent to their final recipients.

    Broadly speaking the mix will process each message in turn: 
        - it derives a shared key (using its private_key), 
        - checks the first hmac,
        - decrypts all other parts,
        - either forwards or decodes the message. 
    """

    G = EcGroup()

    out_queue = []

    # Process all messages
    for msg in message_list:

        ## Check elements and lengths
        if not G.check_point(msg.ec_public_key) or \
               not isinstance(msg.hmacs, list) or \
               not len(msg.hmacs[0]) == 20 or \
               not len(msg.address) == 258 or \
               not len(msg.message) == 1002:
           raise Exception("Malformed input message")

        ## First get a shared key
        shared_element = private_key * msg.ec_public_key
        key_material = sha512(shared_element.export()).digest()

        # Use different parts of the shared key for different operations
        hmac_key = key_material[:16]
        address_key = key_material[16:32]
        message_key = key_material[32:48]

        # Extract a blinding factor for the public_key
        blinding_factor = Bn.from_binary(key_material[48:])
        new_ec_public_key = blinding_factor * msg.ec_public_key

        ## Check the HMAC
        h = Hmac(b"sha512", hmac_key)

        for other_mac in msg.hmacs[1:]:
            h.update(other_mac)

        h.update(msg.address)
        h.update(msg.message)

        expected_mac = h.digest()

        if not secure_compare(msg.hmacs[0], expected_mac[:20]):
            raise Exception("HMAC check failure")

        ## Decrypt the hmacs, address and the message
        aes = Cipher("AES-128-CTR") 

        # Decrypt hmacs
        new_hmacs = []
        for i, other_mac in enumerate(msg.hmacs[1:]):
            # Ensure the IV is different for each hmac
            iv = pack("H14s", i, b"\x00"*14)

            hmac_plaintext = aes_ctr_enc_dec(hmac_key, iv, other_mac)
            new_hmacs += [hmac_plaintext]

        # Decrypt address & message
        iv = b"\x00"*16
        
        address_plaintext = aes_ctr_enc_dec(address_key, iv, msg.address)
        message_plaintext = aes_ctr_enc_dec(message_key, iv, msg.message)

        if final:
            # Decode the address and message
            address_len, address_full = unpack("!H256s", address_plaintext)
            message_len, message_full = unpack("!H1000s", message_plaintext)

            out_msg = (address_full[:address_len], message_full[:message_len])
            out_queue += [out_msg]
        else:
            # Pass the new mix message to the next mix
            out_msg = NHopMixMessage(new_ec_public_key, new_hmacs, address_plaintext, message_plaintext)
            out_queue += [out_msg]

    return out_queue


def mix_client_n_hop(public_keys, address, message):
    """
    Encode a message to travel through a sequence of mixes with a sequence public keys. 
    The maximum size of the final address and the message are 256 bytes and 1000 bytes respectively.
    Returns an 'NHopMixMessage' with four parts: a public key, a list of hmacs (20 bytes each),
    an address ciphertext (256 + 2 bytes) and a message ciphertext (1002 bytes). 

    """
    G = EcGroup()
    # assert G.check_point(public_key)
    assert isinstance(address, bytes) and len(address) <= 256
    assert isinstance(message, bytes) and len(message) <= 1000

    # Encode the address and message
    # use those encoded values as the payload you encrypt!
    address_plaintext = pack("!H256s", len(address), address)
    message_plaintext = pack("!H1000s", len(message), message)

    hmacs = []
    address_cipher = address_plaintext
    message_cipher = message_plaintext

    ## Generate a fresh public key
    private_key = G.order().random()
    client_public_key  = private_key * G.generator()


    blinding_factor = Bn(1)
    new_ec_public_keys = []


    ## ADD CODE HERE
    i = 0
    for public_key in public_keys:
        # We don't want to blind the first key 
        if i == 0:
            new_ec_public_keys.append(public_key)
        else:
            ## First get a shared key
            ## public key part is the last seen public key
            shared_element = private_key * new_ec_public_keys[-1]
            key_material = sha512(shared_element.export()).digest()

            # Building up list of all public keys  - they have been blinded
            blinding_factor *= Bn.from_binary(key_material[48:])
            new_ec_public_keys.append(blinding_factor * public_key)
        i +=1 

    # Want to encrypt message with the first mix's key on the outside - reverse our public keys for this
    for key in reversed(new_ec_public_keys):
          ## First get a shared key
        shared_element = private_key * key
        key_material = sha512(shared_element.export()).digest()

        # Use different parts of the shared key for different operations
        hmac_key = key_material[:16]
        address_key = key_material[16:32]
        message_key = key_material[32:48]

        iv = b"\x00"*16
        # Build cipher on top of cipher from last mix to create message such as P1(P2(P3...(M)...))
        address_cipher = aes_ctr_enc_dec(address_key, iv, address_cipher)
        message_cipher = aes_ctr_enc_dec(message_key, iv, message_cipher)  
        
        ## Check the HMAC
        h = Hmac(b"sha512", hmac_key)        

        # Decrypt hmacs
        new_hmacs = []
        for i, other_mac in enumerate(hmacs):
            # Ensure the IV is different for each hmac
            iv = pack("H14s", i, b"\x00"*14)
            hmac_plaintext = aes_ctr_enc_dec(hmac_key, iv, other_mac)
            h.update(hmac_plaintext)
            new_hmacs += [hmac_plaintext]

        h.update(address_cipher)
        h.update(message_cipher)
        expected_mac = h.digest()[:20]

        hmacs = [expected_mac] + new_hmacs

    return NHopMixMessage(client_public_key, hmacs, address_cipher, message_cipher)



#####################################################
# TASK 4 -- Statistical Disclosure Attack
#           Given a set of anonymized traces
#           the objective is to output an ordered list
#           of likely `friends` of a target user.

import random

def generate_trace(number_of_users, threshold_size, number_of_rounds, targets_friends):
    """ Generate a simulated trace of traffic. """
    target = 0
    others = range(1, number_of_users)
    all_users = range(number_of_users)

    trace = []
    ## Generate traces in which Alice (user 0) is not sending
    for _ in range(number_of_rounds // 2):
        senders = sorted(random.sample( others, threshold_size))
        receivers = sorted(random.sample( all_users, threshold_size))

        trace += [(senders, receivers)]

    ## Generate traces in which Alice (user 0) is sending
    for _ in range(number_of_rounds // 2):
        senders = sorted([0] + random.sample( others, threshold_size-1))
        # Alice sends to a friend
        friend = random.choice(targets_friends)
        receivers = sorted([friend] + random.sample( all_users, threshold_size-1))

        trace += [(senders, receivers)]

    random.shuffle(trace)
    return trace


from collections import Counter

def analyze_trace(trace, target_number_of_friends, target=0):
    """ 
    Given a trace of traffic, and a given number of friends, 
    return the list of receiver identifiers that are the most likely 
    friends of the target.
    """

    ## ADD CODE HERE
    # Dictionary to keep count of how many times a reciever has been sent a message
    receive_count = {}

    for senders, receivers in trace:
        # Only interested in recievers when alice is one of the senders
        if target in senders:
            for potential_friend in receivers:
                if potential_friend in receive_count:
                    receive_count[potential_friend] +=1
                else:
                    receive_count[potential_friend] = 1

    # Sort the dict so that reciever who has been sent the most messages is first
    sorted_counts = sorted(receive_count.items(), key=lambda kv: kv[1], reverse=True)

    # take the first n recievers where n is the target number of friends
    friends = [x for (x, y) in sorted_counts[:target_number_of_friends]]

    return friends

## TASK Q1 (Question 1): The mix packet format you worked on uses AES-CTR with an IV set to all zeros. 
#                        Explain whether this is a security concern and justify your answer.

""" TODO: Your answer HERE """
'''It is very imortant when using AES_CTR that the same IV is not used with the same key to encrypt a message 
as it is this that would cause serious security concerns. Re-using an IV and key would effectively give away the plaintext of a message, reducing the privacy of our message.
In our implementation, we are creating a random private key which is then used along with the IV in the encryption algorithm. 
However, we cannot assume that the same private key would be produced more than once - whilst the probability is small it is not impossible and therefore using an IV set to all zeros could cause security concern. 
Producing a new, random IV each time would therefore improve the security of our implementation. 

'''


## TASK Q2 (Question 2): What assumptions does your implementation of the Statistical Disclosure Attack 
#                        makes about the distribution of traffic from non-target senders to receivers? Is
#                        the correctness of the result returned dependent on this background distribution?

""" TODO: Your answer HERE """
'''The implemenation assumes that friends of Alice would only exist in traces where Alice exists as a sender.
 We are assuming that receivers who receive most messages most frequently in these traces are more likely to be Alice's friends. 
 We are also assuming that there is no latency in the traffic and that all receivers are sent messages from a sender in that same trace and that there is no delay. 
 The correctness of the result does depend on this assumption as a delay in receiving a packet would produce different results

'''
