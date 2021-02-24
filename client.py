import socket
import signal
import sys
import random
import json
import string
import time
from domino import Player, Domino
from Diffie_v2 import DiffieHellman
from ast import literal_eval

# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from Crypto.PublicKey import RSA 
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Cipher import PKCS1_OAEP
from hashlib import blake2b
from hmac import compare_digest

import pickle
import hashlib
import binascii
import secrets
import hmac

class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (bytes, bytearray)):
            print("obj", obj)
            print("type", type(obj))
            return obj.decode('raw_unicode_escape') # <- or any other encoding of your choice
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)

class Client:
    def __init__( self, address, port, username ):
        self.socket = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
        self.socket.connect( ( address, port ) )
        self.player = None
        self.game = None
        self.bitCommit = None
        self.bitCommitR1 = None
        self.bitCommitR2 = None
        self.bitCommitT = None
        self.bitcommits = {}
        self.keymap = {}
        self.username = username
        self.cheated = False
        self.hands = {}
        self.r2s = {}
        self.diffieinstances = {}
        self.diffiekeys = {}
        self.join( )
        self.receive_package( )

    def join( self ):
        # Ask server to play
        package = { "message-type": "join", "data": "Client wants to join table manager.\n" }
        # Send byte package to table manager
        self.socket.send( self.toByte( package ) )
        # Response from server to packate type wantToJoin
        package = self.socket.recv( 16384 )
        package = self.toObject( package )
        print( 'Server join response: {}'.format( package["data"] ) )
        npiecesplayer = { 2:7, 3:6, 4:5 }
        self.player = Player( self.username, self.socket, npiecesplayer.get( package["nplayers"], 0 ) )
        self.game = Domino( npiecesplayer.get( package["nplayers"] ) )
        self.game.nplayers = package["nplayers"]
        print( "Number of players: ", self.game.nplayers )
        print( "Number of pieces: ", npiecesplayer.get( package["nplayers"], 0 ) )
        
        if( package["data"] != "200" ):
            sys.exit( 0 )

        return

    def receive_package( self ):
        while True:
            try:
                # Signal to exit
                signal.signal( signal.SIGINT, self.signal_handler )

                package = b''
                while True:
                    # Receive packages from client
                    part = self.socket.recv( 4096 )
                    package += part
                    if len(part) < 4096:
                        break

                #package = self.socket.recv( 16384 )

                if( package ):
                    package = self.toObject( package )
                    self.handle( package )
            except( socket.timeout, socket.error):
                print( 'Server error, system exit!\n' )
                sys.exit( 0 )

    def toByte( self, package ):
        # package = json.dumps( package, indent=4 )
        # package = package.encode( )
        package = pickle.dumps( package )
        return package

    def toByteUtf8 (self, package):
        package = json.dumps(package).encode('utf-8')
        return package

    def toObject( self, package ):
        # package = package.decode( )
        # package = json.loads( package )
        package = pickle.loads( package )
        return package

    def signal_handler(self, signal, frame):
        print('\nDone!')

        self.socket.shutdown( socket.SHUT_RDWR )
        self.socket.close( )
        sys.exit( 0 )

    def stringify_keys( self, d ):
        newl = []
        for key, value in d.items():
            # print("key ->",key)
            # print("value ->",value)
            strkey = key.decode('raw_unicode_escape')
            value = value.decode('raw_unicode_escape')
            # strkey = key.decode('ascii')
            # value = value.decode('ascii')
            # print("strkey ->",strkey)
            newl.append((strkey,value))
            # newd[strkey] = value
        return newl

    def unstringify_keys( self, d ):
        newd = {}
        for key, value in d:
            # newkey = literal_eval(key)
            newkey = key.encode('raw_unicode_escape')
            newvalue = value.encode('raw_unicode_escape')
            newd[newkey] = newvalue
        return newd

    def stringify_values( self, d ):
        newl = []
        for key, value in d.items():
            # print("key ->",key)
            # print("value ->",value)
            value = value.decode('raw_unicode_escape')
            # strkey = key.decode('ascii')
            # value = value.decode('ascii')
            # print("strkey ->",strkey)
            newl.append((key,value))
            # newd[strkey] = value
        return newl

    def unstringify_values( self, d ):
        newd = {}
        for key, value in d:
            # newkey = literal_eval(key)
            newvalue = value.encode('raw_unicode_escape')
            newd[key] = newvalue
        return newd

    def stringify_valuesofvalues( self, d ):
        newl = []
        for key, value in d.items():
            values = []
            for key2, value2 in value.items():
                key2 = key2.decode('raw_unicode_escape')
                value2 = value2.decode('raw_unicode_escape')
                values.append( (key2, value2) )
            newl.append((key,values))
        return newl

    def unstringify_valuesofvalues( self, d ):
        newd = {}
        for key, values in d:
            newvalues = {}
            for key2, value2 in values:
                key2 = key2.encode('raw_unicode_escape')
                value2 = value2.encode('raw_unicode_escape')
                newvalues[key2] = value2
            newd[key] = newvalues
        return newd
    
    def stringify_tuples( self, d ):
        newl = []
        for key, value in d.items():
            print("key ->",key)
            print("value ->",value)
            if type(value) == tuple:
                value1 = value[0].decode('raw_unicode_escape')
                value2 = value[1].decode('raw_unicode_escape')
                # strkey = key.decode('ascii')
                # value = value.decode('ascii')
                # print("strkey ->",strkey)
                newl.append( ( key, (value1,value2) ) )
                # newd[strkey] = value
        return newl

    def unstringify_tuples( self, d ):
        newd = {}
        for key, value in d:
            if type(value) == tuple:
                # newkey = literal_eval(key)
                newvalue1 = value[0].encode('raw_unicode_escape')
                newvalue2 = value[1].encode('raw_unicode_escape')
                newd[key] = ( newvalue1, newvalue2 )
        return newd

    def tolist( self, d ):
        newl = []
        for key, value in d.items():
            newl.append((key,value))
        return newl

    def todict( self, d ):
        newd = {}
        for key, value in d:
            newd[key] = value
        return newd

    def getRandomNumber(self, length=6):
        #print("sera")
        password = string.digits
        result_password = ''.join(secrets.choice(password) for i in range(length))
        return result_password

    def bitCommitment(self, hand):
        #print("siga")
        #var = self.toByteUtf8(hand)
        #print("ja passouuu")

        #hand = var
        self.bitCommitR1 = self.getRandomNumber()
        self.bitCommitR2 = self.getRandomNumber()

        #print("var", var)
        print("R1", self.bitCommitR1)

        hashFunction = hashlib.sha256()

        for key, value in hand.items():
            hashFunction.update(key)
            hashFunction.update(value)

        hashFunction.update(bytes(int(self.bitCommitR1)))
        hashFunction.update(bytes(int(self.bitCommitR2)))
        #hashFunction.update(bytes(hand))
        #print("hash", hashFunction)

        #self.bitCommit = hashFunction.digest() #
        self.bitCommit = hashFunction.hexdigest() # hexadecimal (string type)
        #print(binascii.hexlify(hashFunction.digest())) # hexdigest in bytes
        print("bitCommit", self.bitCommit)

        return self.bitCommitR1, self.bitCommitR2, hand

    def checkBitCommitment(self, hand, r1, r2):
        
        hashFunction = hashlib.sha256()

        for key, value in hand.items():
            hashFunction.update(key)
            hashFunction.update(value)

        hashFunction.update(bytes(int(r1)))
        hashFunction.update(bytes(int(r2)))

        return hashFunction.hexdigest()

    def verify(self, hash1, hash2):
        return compare_digest(hash1, hash2)

    def hmac_sha512(self, key, msg):
        return hmac.new(msg, key, hashlib.sha512)

    def handle( self, package ):
        mtype = package["message-type"]
        data = package["data"]

        if( mtype == "diffie" ):
            client = package["client"]
            loaded_public_key = serialization.load_pem_public_key(package["data"])
            print("Loaded public key from server: ", loaded_public_key)
            # Save public key sent by server in dicionary with key = nplayers
            self.diffiekeys[self.game.nplayers] = loaded_public_key
            # Generate my keys to share with server
            self.diffieinstances[self.game.nplayers] = DiffieHellman()
            clientDiffie = self.diffieinstances.get( self.game.nplayers )
            # Send to server the public key generated to comunicate with server
            serialized_public = clientDiffie.publicKey.public_bytes(encoding=serialization.Encoding.PEM
                , format=serialization.PublicFormat.SubjectPublicKeyInfo)
            package = { "message-type": "diffie", "data": serialized_public, "client": client }
            # text = "Sprynger is dumb"
            # cipheredMessage = self.diffieinstances.get(self.game.nplayers).encrypt(self.diffiekeys.get(self.game.nplayers), text)
            # shared_key = self.diffieinstances.get(self.game.nplayers).shared_key( self.diffiekeys.get(self.game.nplayers) )
            # print("shared key: ", shared_key)
            
            # package = { "message-type": "diffie", "data": serialized_public, "client": client
            # , "cipheredMessage": cipheredMessage, "iv": self.diffieinstances.get(self.game.nplayers).IV }
            self.socket.send( self.toByte( package ) )

        if( mtype == "diffie-clients" ):
            client = package["client"]

            if( package["save-back"] ):
                # Last keys to be saved
                loaded_public_key = serialization.load_pem_public_key(package["data"])
                self.diffiekeys[package["from"]] = loaded_public_key
                print("TERCEIRO, GUARDAR: Guardei a chave pública do cliente {} que é: {}".format(package["from"], loaded_public_key) )

            # Send keys to other clients
            elif( package["send"] ):
                for i in range( client+1, self.game.nplayers):
                    # Gerar as instâncias Diffie-Helman entre clientes
                    self.diffieinstances[i] = DiffieHellman()
                    print("PRIMEIRO, SEND: Eu Cliente{} mandei a sua chave pública para o cliente {} que é: {}".format( client, i, self.diffieinstances.get(i).publicKey ))
                    # Mandar as chaves públicas para os clientes do agreement
                    serialized_public = self.diffieinstances.get(i).publicKey.public_bytes(encoding=serialization.Encoding.PEM
                        , format=serialization.PublicFormat.SubjectPublicKeyInfo)
                    package = { "message-type": "diffie-clients", "data": serialized_public
                        , "client": i, "send": False, "from": client, "save-back": False }
                    self.socket.send( self.toByte( package ) )

            # Save keys received from clientes and send corresponding key
            else:
                loaded_public_key = serialization.load_pem_public_key(package["data"])
                self.diffiekeys[package["from"]] = loaded_public_key
                print("SEGUNDO, GUARDAR, SEND: Recebi a chave pública do cliente {} que é: {}".format(package["from"], loaded_public_key) )
                # Gerar e mandar a chave correspondente do agreement para o cliente que me mandou
                self.diffieinstances[package["from"]] = DiffieHellman()
                serialized_public = self.diffieinstances.get(package["from"]).publicKey.public_bytes(encoding=serialization.Encoding.PEM
                        , format=serialization.PublicFormat.SubjectPublicKeyInfo)
                package = { "message-type": "diffie-clients", "data": serialized_public
                    , "client": package["from"], "send": False, "from": client, "save-back": True }
                self.socket.send( self.toByte( package ) )

        if( mtype == "shuffle" ):
            # Check if packet came from server
            received_hmac = package["hmac"]
            dh_instance = self.diffieinstances.get(self.game.nplayers)
            verify_hmac = dh_instance.hmac_sha512( self.toByte( package["data"] )
                , self.diffiekeys.get(self.game.nplayers) )
            print("Did the data came from expected entity and is it ok ? --> ",self.verify(received_hmac, verify_hmac.digest()) )
            if( not self.verify(received_hmac, verify_hmac.digest()) ):
                sys.exit(1)
            # Shuffling deck
            #print("package[\"data\"] ->", package["data"])
            if ( package["firstToEncrypt"] == False ):
                self.game.dominoset = self.unstringify_keys( data )
                #print("self.unstringify_keys(package[\"data\"]) ->", self.game.dominoset)

            else:
                self.game.dominoset = data.copy()
            
            #print("i received the set ->", self.game.dominoset)
            self.game.stageRandomization( self.player.map, package["firstToEncrypt"] )
            # Generate hmac
            hmac = dh_instance.hmac_sha512( self.toByte(self.stringify_keys( self.game.dominoset ))
                , self.diffiekeys.get(self.game.nplayers) ).digest()
            package = { "message-type": "shuffle", "data": self.stringify_keys( self.game.dominoset )
                , "hmac": hmac, "client": package["client"] }
            # Send deck to server
            #print( "package", package )
            #print( "type( package[\"data\"] )", type( package["data"] ) )
            package = self.toByte( package )
            # print( "self.toByte( package )", package )
            self.socket.send( package )
            print("I shuffled the deck and sent it back to server!")

            # print("AFTER ENCRYPTION", self.player.map)
        
        if( mtype == "selection" ):
            # Check if packet came from server
            received_hmac = package["hmac"]
            dh_instance = self.diffieinstances.get(self.game.nplayers)
            verify_hmac = dh_instance.hmac_sha512( self.toByte( package["data"] )
                , self.diffiekeys.get(self.game.nplayers) )
            # print("Received hmac: ", received_hmac)
            # print("Generated hmac: ", verify_hmac.digest())
            print("Did the data came from expected entity and is it ok ? --> ",self.verify(received_hmac, verify_hmac.digest()) )
            if( not self.verify(received_hmac, verify_hmac.digest()) ):
                sys.exit(1)
            # If the message was redirected by server from another player it is encrypted. Decrypt it
            if( package["cyphered"] ):
                dh = self.diffieinstances.get( package["from"] )
                data = dh.decrypt( self.diffiekeys.get( package["from"] ), data, package["iv"] )
                data = json.loads(data)
                data = self.unstringify_keys(data)
                # print("\t Data decifrada --> ", data)

            # print("DATA", data)
            # Randomly select either pick up a (random) tile or back off
            choice = random.randint( 1, 100 )
            # Pick up a (random) tile
            #print("LENGTH OF HAND BEFORE", len(self.player.hand))
            if( choice <= 5 and ( len( self.player.hand ) != self.game.npiecesplayer ) ):
                # Retrive from deck piece with first index
                index = next( iter( data ) )
                # piece = data.pop( ) NAO E UM LIST, E UM DICT
                piece = data.pop( index )
                # self.player.hand.append( ( index, piece ) )
                self.player.hand[index] = piece
                # print( "I picked a random tile, this tile: ", piece )
                # print( "This is my hand", self.player.hand )
                # print("LENGTH OF HAND AFTER", len(self.player.hand))
            
            # Back off 95%
            else:
                choice = random.randint( 0, 1 )
                # Mantain stock as it is
                if( choice == 0 ):
                    print("I didn't mess up the stock.")
                
                # Swap some or all pieces
                else:
                    #print("LENGTH OF DATA BEFORE", len(data.copy()))
                    if( len( self.player.hand ) >= 1 ):
                        nswitchpieces = random.randint( 1, len( self.player.hand ) )
                        for i in range( nswitchpieces ):
                            # swap = self.player.hand.pop( i )
                            # idx, tile = random.choice(list(data.items()))
                            # del data[idx]
                            # self.player.hand.append( ( idx, tile ) )
                            # data[ swap[0] ] = swap[1]
                            swapidx, swaptile = random.choice(list(self.player.hand.items()))
                            idx, tile = random.choice(list(data.items()))
                            del data[idx]
                            self.player.hand[ idx ] = tile
                            data[ swapidx ] = swaptile
                            del self.player.hand[swapidx]
                            
                        print("I swaped {} pieces!".format( nswitchpieces ) )
                    else:
                        print("I don't have pieces too swap!")
                    #print("LENGTH OF DATA AFTER", len(data.copy()))
                    
            #print("len( data ) -> {} == ( len( self.game.dominoset ) -> {} - self.player.npieces -> {} * self.game.nplayers -> {} )"
                #.format( len( data ), len( self.game.dominoset ), self.game.npiecesplayer, self.game.nplayers ))
            if( len( data ) == ( len( self.game.dominoset ) - self.game.npiecesplayer * self.game.nplayers )  ):
                # Generate hmac
                hmac = dh_instance.hmac_sha512( self.toByte(data)
                    , self.diffiekeys.get(self.game.nplayers) ).digest()
                package = { "message-type": "selection", "data": data, "players-ready": True
                , "hmac": hmac, "client": package["from"], "from": package["client"], "cyphered": False }
                print("Number of pieces in my hand: ", len( self.player.hand ) )
                print("LENGTH OF DATA AFTER STAGE IS FINISHED", len(data.copy()))
            else:
                # Redirect to a random player
                index = random.randint( 0, self.game.nplayers-1 )
                while index == package["client"]:
                    index = random.randint( 0, self.game.nplayers-1 )
                # Encrypt message that will be redirect to another player by server
                # print("Quero chegar a isto: ", data)
                dh = self.diffieinstances.get(index)
                data = self.stringify_keys(data)
                data = json.dumps(data)
                print("Eu sou este cliente: ", package["client"])
                print("clientes para onde vai mandar: ",index)
                data = dh.encrypt( self.diffiekeys.get(index), data )
                # Generate hmac
                hmac = dh_instance.hmac_sha512( self.toByte(data)
                    , self.diffiekeys.get(self.game.nplayers) ).digest()
                # print("\t Data cifrada --> ", data)
                package = { "message-type": "selection", "data": data, "players-ready": False
                    , "hmac": hmac, "client": index, "from": package["client"], "cyphered": True, "iv": dh.IV }
            self.socket.send( self.toByte( package ) )

        if( mtype == "commitment" ):
            print("commitment stage")
            # Check if packet came from server
            received_hmac = package["hmac"]
            dh_instance = self.diffieinstances.get(self.game.nplayers)
            verify_hmac = dh_instance.hmac_sha512( self.toByte( package["data"] )
                , self.diffiekeys.get(self.game.nplayers) )
            print("Did the data came from expected entity and is it ok ? --> ",self.verify(received_hmac, verify_hmac.digest()) )
            if( not self.verify(received_hmac, verify_hmac.digest()) ):
                sys.exit(1)
                
            if ( package["save"] ):
                # Generate hmac
                hmac = dh_instance.hmac_sha512( self.toByte("")
                    , self.diffiekeys.get(self.game.nplayers) ).digest()
                self.bitcommits = package["data"]
                print( "Mapa dos bitcommits no cliente: " , self.bitcommits)
                package = { "message-type": "commitment", "save": True, "data": ""
                    , "hmac": hmac, "client": package["client"] }
                self.socket.send( self.toByte( package ) )
            else:
                iam = package["youare"]
                print("I am", iam)
                self.player.pid = int(iam)
                # All players perform bitcommit
                self.bitCommitment( self.player.hand )
                # All players save stock left in selection stage
                self.player.stock = package["stock"]
                # print("This is the stock: ", self.player.stock)
                print("Length of the stock: ", len(self.player.stock))
                # Generate hmac
                hmac = dh_instance.hmac_sha512( self.toByte([ self.bitCommitR1, self.bitCommit ])
                    , self.diffiekeys.get(self.game.nplayers) ).digest()
                package = { "message-type": "commitment", "username": self.username, "save": False, "iam": self.player.pid
                ,"data": [ self.bitCommitR1, self.bitCommit ], "hmac": hmac, "client": package["client"] }
                self.socket.send( self.toByte( package ) )

        if( mtype == "revelation" ):
            print("revelation stage")
            # Check if packet came from server
            received_hmac = package["hmac"]
            dh_instance = self.diffieinstances.get(self.game.nplayers)
            verify_hmac = dh_instance.hmac_sha512( self.toByte( package["data"] )
                , self.diffiekeys.get(self.game.nplayers) )
            print("HERE Did the data came from expected entity and is it ok ? --> ",self.verify(received_hmac, verify_hmac.digest()) )
            if( not self.verify(received_hmac, verify_hmac.digest()) ):
                sys.exit(1)
                
            # print("DATA REVELATION IN", data)
            # print("STOCK", self.player.stock)
            if( package["firstToDecrypt"] == False ):
                # Decifrar o stock com as chaves recebidas e mandar as chaves dele para o next player
                # Isto é o que é recebido do cliente anterior

                # if i have keys from player 2 then i must be player 3
                if self.game.map3:
                    data = {}
                    # obtain t1 with k2 and t2
                    t1s = []
                    for key2, tile2 in self.game.map3.items():
                        self.game.writeDecypher("tmp_p.txt", tile2)
                        ti1 = self.game.aesDecypher(tile2, key2)
                        t1s.append( ti1 )
                    for index_pseud1, key1 in self.player.map.items():
                        tile1 = index_pseud1[1]
                        if tile1 in t1s:
                            data[key1] = tile1
                            # print("\tThis was decrypted from the other player")
                        else:
                            # print("\tThis was not")
                            pass
                
                # if i have keys from player 1 then i must be player 2
                elif self.game.map2:
                    data = {}
                    # obtain t2 with k3 and t3
                    t2s = []
                    for key3, tile3 in self.game.map2.items():
                        self.game.writeDecypher("tmp_p.txt", tile3)
                        ti2 = self.game.aesDecypher(tile3, key3)
                        t2s.append( ti2 )
                    for index_pseud2, key2 in self.player.map.items():
                        tile2 = index_pseud2[1]
                        if tile2 in t2s:
                            data[key2] = tile2
                            # print("\tThis was decrypted from the other player")
                        else:
                            # print("\tThis was not")
                            pass
                
                # if i have keys from player 0 then i must be player 1
                elif self.game.map1:
                    data = {}
                    # obtain t3 with k4 and t4
                    t3s = []
                    for key4, tile4 in self.game.map1.items():
                        # print("KEY //", key4)
                        # print("TILE //", tile4)
                        self.game.writeDecypher("tmp_p.txt", tile4)
                        ti3 = self.game.aesDecypher(tile4, key4)
                        t3s.append( ti3 )
                    for index_pseud3, key3 in self.player.map.items():
                        tile3 = index_pseud3[1]
                        if tile3 in t3s:
                            data[key3] = tile3
                            # print("\tThis was decrypted from the other player")
                        else:
                            # print("\tThis was not")
                            pass

                print("ENVIEI", len(data), "CHAVES")

            else:
                # Primeiro jogador a decifrar o stock
                # Vai ao stock das peças não escolhidas e faz o que o génio sabe que faz
                data = {}
                # print( "\n STOCK ", dict( self.player.stock.copy() ) )
                for index_pseud, key in self.player.map.items():
                    tile = index_pseud[1]
                    #print("\nIterating pair key", key, "\n tile", tile)
                    # stock passa temporariamente de (idx, tile) para idx: tile
                    # para ser mais facil de checkar
                    if tile in dict( self.player.stock.copy() ).values():
                        # print("\tThis pair is in the stock. We don't want to reveal it")
                        pass
                    else:
                        # print("\tWe want to reveal this pair")
                        # data = "chaves (e peças) que tem que mandar WARNING:MUDAR (sou o primeiro a decifrar!)"
                        data[key] = tile
                print("ENVIEI", len(data), "CHAVES")

            # Aqui manda as chaves e as peças para o próximo jogador
            # Generate hmac
            hmac = dh_instance.hmac_sha512( self.toByte(data)
                , self.diffiekeys.get(self.game.nplayers) ).digest()
            package = { "message-type": "revelation", "data": data
                ,"hmac": hmac, "client": package["client"] }
            # Send deck to server
            package = self.toByte( package )
            self.socket.send( package )
            print("I send the keys that i used in randomization stage to the next client!")
            print("My user name is: ", self.username)
        
        if( mtype == "revelation-save" ):
            print("revelation save stage\n")
            # Check if packet came from server
            received_hmac = package["hmac"]
            dh_instance = self.diffieinstances.get(self.game.nplayers)
            verify_hmac = dh_instance.hmac_sha512( self.toByte( package["data"] )
                , self.diffiekeys.get(self.game.nplayers) )
            print("Did the data came from expected entity and is it ok ? --> ",self.verify(received_hmac, verify_hmac.digest()) )
            if( not self.verify(received_hmac, verify_hmac.digest()) ):
                sys.exit(1)
                
            #WARNING: guardar chaves recebidas do server (todas as chaves de todos os clientes)
            # cliente que enviou
            client = package["client"]
            print("Recebi chaves !!!! client", client)
            if client == 0: # SIM ESTE FOI O ULTIMO A ENCRIPTAR
                print("Stored keys from client 0 (map1)")
                self.game.map1 = data
            elif client == 1:
                print("Stored keys from client 1 (map2)")
                self.game.map2 = data
            elif client == 2:
                print("Stored keys from client 2 (map3)")
                self.game.map3 = data
            elif client == 3:
                print("Stored keys from client 3 (map4)")
                self.game.map4 = data

            # package = { "message-type": "revelation-save", "data": "" }
            # package = self.toByte( package )
            # self.socket.send( package )

        if( mtype == "revelationdone" ):
            print("Revelation stage done!")
            # Check if packet came from server
            received_hmac = package["hmac"]
            dh_instance = self.diffieinstances.get(self.game.nplayers)
            verify_hmac = dh_instance.hmac_sha512( self.toByte( package["data"] )
                , self.diffiekeys.get(self.game.nplayers) )
            print("Did the data came from expected entity and is it ok ? --> ",self.verify(received_hmac, verify_hmac.digest()) )
            if( not self.verify(received_hmac, verify_hmac.digest()) ):
                sys.exit(1)
            # self.player.hand[index] = tile

            iam = package["youare"]
            print("I am", iam)
            self.player.pid = int(iam)
            tmpmap = {}
            for index_pseud, key in self.player.map.items():
                tmpmap[key] = index_pseud[1]

            for i, ti in self.player.hand.items():
                # print("\n\n")
                # print( self.game.map1 )
                tmpmap1 = {}
                if self.game.map1:
                    print("Using map1")
                    tmpmap1 = self.game.map1.copy()
                    # print("self.game.map1\n", tmpmap1)
                else:
                    print("Using my map1")
                    tmpmap1 = tmpmap.copy()
                    # print("self.player.map\n", tmpmap1)

                for key, pseud in tmpmap1.items():
                    # print("ti", ti)
                    # print("pseud", pseud)
                    # print(pseud == ti)
                    if(pseud == ti):
                        
                        self.game.writeDecypher("tmp_i.txt", i)
                        self.game.writeDecypher("tmp_p.txt", ti)

                        i = self.game.aesDecypher(i, key)
                        
                        ti = self.game.aesDecypher(ti, key)

                        # print("\nINDEX QUE EU QUERO ENCONTRAR NO MAPA 3")
                        # print(i)
                        # print("PSEUDONIMO TAL TAL TAL")
                        # print(ti)
                        break

                # time.sleep(2)

                if self.game.nplayers >= 2:
                    tmpmap2 = {}
                    if self.game.map2:
                        print("Using map2")
                        tmpmap2 = self.game.map2.copy()
                        # print("self.game.map2\n", tmpmap2)
                    else:
                        print("Using my map2")
                        tmpmap2 = tmpmap.copy()
                        # print("self.player.map\n", tmpmap2)

                    for key, pseud in tmpmap2.items():
                        # print(pseud == ti)
                        if(pseud == ti):

                            self.game.writeDecypher("tmp_i.txt", i)
                            self.game.writeDecypher("tmp_p.txt", ti)

                            i = self.game.aesDecypher(i, key)
                            
                            ti = self.game.aesDecypher(ti, key)

                            # print("index",i,"pseud",ti)
                            break

                # time.sleep(2)

                if self.game.nplayers >= 3:
                    tmpmap3 = {}
                    if self.game.map3:
                        print("Using map3")
                        tmpmap3 = self.game.map3.copy()
                    else:
                        print("Using my map3")
                        tmpmap3 = tmpmap.copy()

                    for key, pseud in tmpmap3.items():
                        print(pseud == ti)
                        if(pseud == ti):

                            self.game.writeDecypher("tmp_i.txt", i)
                            self.game.writeDecypher("tmp_p.txt", ti)

                            i = self.game.aesDecypher(i, key)
                            
                            ti = self.game.aesDecypher(ti, key)

                            # print("index",i,"pseud",ti)
                            break

                if self.game.nplayers == 4:
                    print("Game has 4 players")
                    tmpmap4 = {}
                    if self.game.map4:
                        tmpmap4 = self.game.map4.copy()
                    else:
                        tmpmap4 = tmpmap.copy()

                    for key, pseud in tmpmap4.items():
                        print(pseud == ti)
                        if(index == i and pseud == ti):

                            self.game.writeDecypher("tmp_i.txt", i)
                            self.game.writeDecypher("tmp_p.txt", ti)

                            i = self.game.aesDecypher(i, key)
                            
                            ti = self.game.aesDecypher(ti, key)

                            # print("index",i,"pseud",ti)
                            break
                
                i = i.decode()
                ti = ti.decode()

                print("index", i, "\ncorresponde ao tile", ti)

                self.player.decryptedhand[i] = ti
            
            print("My decrypted hand\n", self.player.decryptedhand)
            print("Length of my decrypted hand", len(self.player.decryptedhand))

        if( mtype == "anonprep" ):
            # Check if packet came from server
            received_hmac = package["hmac"]
            dh_instance = self.diffieinstances.get(self.game.nplayers)
            verify_hmac = dh_instance.hmac_sha512( self.toByte( package["data"] )
                , self.diffiekeys.get(self.game.nplayers) )
            print("Did the data came from expected entity and is it ok ? --> ",self.verify(received_hmac, verify_hmac.digest()) )
            if( not self.verify(received_hmac, verify_hmac.digest()) ):
                sys.exit(1)

            if( package["cyphered"] ):
                dh = self.diffieinstances.get( package["from"] )
                data = dh.decrypt( self.diffiekeys.get( package["from"] ), data, package["iv"] )
                data = json.loads(data)
                #data = self.todict( data.copy() )
                data = self.unstringify_values(data)
                keys = data.copy()
                # data = self.todict( data.copy() )
                # data = self.unstringify_keys(data)
                for kindex, key in keys.items():
                    if keys[kindex] == b"":
                        keys[kindex] = ""
                # print("\t Data decifrada --> ", keys)
            else:
                keys = self.todict( data.copy() )

            choice = random.randint( 1, 100 )

            # print("\nINDEX KEYS", keys)

            # print("\nMY KEY MAP", self.keymap)

            keys_inserted = 0
            for index, tile in self.player.decryptedhand.items():
                for kindex, key in keys.items():
                    # print("\nindex", index, "kindex", kindex)
                    # print("type(index)", type(index))
                    # print("type(kindex)", type(kindex))
                    # print("type ( keys[kindex] )", type ( keys[kindex] ) )
                    # print("keys[kindex] != ''", keys[kindex] != "" )
                    # print("int(index) == int(kindex)", int(index) == int(kindex))
                    # print("keys[kindex] != bytes()", keys[kindex] != bytes())
                    if int(index) == int(kindex) and keys[kindex] != "":
                        # print("\nindex", index, "kindex", kindex)
                        # print("type(index)", type(index))
                        # print("type(kindex)", type(kindex))
                        # print("keys[kindex]", keys[kindex])
                        # print("int(index) == int(kindex)", int(index) == int(kindex))
                        # print("keys[kindex] != bytes()", keys[kindex] != bytes())
                        keys_inserted += 1
                        # print("\tkeys_inserted +1", keys_inserted)

            # print("keys_inserted", keys_inserted, "max?", keys_inserted == self.game.npiecesplayer)
            if( choice <= 5 and keys_inserted != self.game.npiecesplayer ):
                # insert a key that has not been inserted
                inserted = False
                for index, tile in self.player.decryptedhand.items():
                    for kindex, key in keys.items():
                        if (not inserted) and int(index) == int(kindex) and keys[kindex] == "":

                            keypair = RSA.generate(2048)
                            
                            pubkey = keypair.publickey()

                            pem = pubkey.export_key('PEM')

                            # msg = b'A message for encryption'
                            # encryptor = PKCS1_OAEP.new(pubkey)
                            # encrypted = encryptor.encrypt(msg)
                            # print("Encrypted:", binascii.hexlify(encrypted))

                            # pubkey2 = RSA.import_key(pem)

                            # msg2 = b'A message for encryption'
                            # encryptor2 = PKCS1_OAEP.new(pubkey2)
                            # encrypted2 = encryptor.encrypt(msg2)
                            # print("Encrypted:", binascii.hexlify(encrypted2))

                            # decryptor = PKCS1_OAEP.new(keypair)
                            # decrypted = decryptor.decrypt(encrypted)
                            # print('Decrypted:', decrypted)

                            # decryptor2 = PKCS1_OAEP.new(keypair)
                            # decrypted2 = decryptor.decrypt(encrypted2)
                            # print('Decrypted:', decrypted2)

                            keys[kindex] = pem
                            self.keymap[index] = ( pubkey, keypair )
                            print("I inserted a key ->", index, "\nTotal", keys_inserted+1)
                            inserted = True
                if not inserted:
                    print("INSERT FAILED\nINSERT FAILED\nINSERT FAILED\nINSERT FAILED\n")
            else:
                # print("I backed off")
                pass

            total_keys_inserted = 0
            for kindex, key in keys.items():
                if keys[kindex] != "":
                    total_keys_inserted += 1
            # print("total_keys_inserted", total_keys_inserted)

            # Choose next player to do de-anonymization
            rplayer = random.randint( 0, self.game.nplayers-1 )
            while rplayer == package["client"]:
                    rplayer = random.randint( 0, self.game.nplayers-1 )

            # Current client
            cclient = package["client"]

            if( total_keys_inserted == ( self.game.nplayers * self.game.npiecesplayer ) ):
                # done
                # Generate hmac
                hmac = dh_instance.hmac_sha512( self.toByte(self.tolist(keys.copy()))
                    , self.diffiekeys.get(self.game.nplayers) ).digest()
                print("done")
                package = { "message-type": "anonprep", "data": self.tolist(keys.copy()), "players-ready": True
                    ,"hmac": hmac, "client": rplayer, "from": cclient, "cyphered": False }
                # package = { "message-type": "anonprep", "data": keys.copy(), "players-ready": True }
            else:
                # Encrypt message that will be redirect to another player by server
                # print("Quero chegar a isto: ", keys.copy())
                for kindex, key in keys.items():
                    if keys[kindex] == "":
                        keys[kindex] = b""
                dh = self.diffieinstances.get(rplayer)
                #data = self.stringify_keys(keys.copy())
                data = self.stringify_values(keys.copy())
                #data = self.tolist(data)
                data = json.dumps(data)
                data = dh.encrypt( self.diffiekeys.get(rplayer), data )
                # Generate hmac
                hmac = dh_instance.hmac_sha512( self.toByte(data)
                    , self.diffiekeys.get(self.game.nplayers) ).digest()
                # not done
                package = { "message-type": "anonprep", "data": data, "players-ready": False
                    ,"hmac": hmac, "client": rplayer, "from": cclient, "cyphered": True, "iv": dh.IV }
                
                # package = { "message-type": "anonprep", "data": keys.copy(), "players-ready": False }
            
            package = self.toByte( package )
            self.socket.send( package )

        if( mtype == "deanon" ):
            # Check if packet came from server
            received_hmac = package["hmac"]
            dh_instance = self.diffieinstances.get(self.game.nplayers)
            verify_hmac = dh_instance.hmac_sha512( self.toByte( package["data"] )
                , self.diffiekeys.get(self.game.nplayers) )
            print("Did the data came from expected entity and is it ok ? --> ",self.verify(received_hmac, verify_hmac.digest()) )
            if( not self.verify(received_hmac, verify_hmac.digest()) ):
                sys.exit(1)
            
            # self.player.pseuddecryptedhand = self.unstringify_tuples( data.copy() )

            tiles = self.unstringify_tuples( data.copy() )

            print("TILES", tiles)

            for index, pair in tiles.items():
                cipher_tile = pair[0]
                #print("cipher_tile", cipher_tile)
                for index2, pair2 in self.keymap.items():
                    keypair = pair2[1]
                    print("index", index, "index2", index2)
                    if int(index) == int(index2): # the index that server shared, is in my keymap
                        # decrypt the ciphered tile of that index
                        decryptor = PKCS1_OAEP.new(keypair)
                        decrypted = decryptor.decrypt(cipher_tile).decode()
                        print('index:', index, "tile", decrypted)
                        realtile = ( decrypted[0] , decrypted[1] )
                        self.player.pseuddecryptedhand[index] = realtile
                        self.player.pseuddecryptedhandINIT[index] = realtile





        # GAME ON

        if( mtype == "yourturn" ):
            # Check if packet came from server
            received_hmac = package["hmac"]
            dh_instance = self.diffieinstances.get(self.game.nplayers)
            verify_hmac = dh_instance.hmac_sha512( self.toByte( package["data"] )
                , self.diffiekeys.get(self.game.nplayers) )
            print("Did the data came from expected entity and is it ok ? --> ",self.verify(received_hmac, verify_hmac.digest()) )
            if( not self.verify(received_hmac, verify_hmac.digest()) ):
                sys.exit(1)

            if "stockpickresult" in package:
                index = next(iter(package["stockpickresult"]))
                stocktile = package["stockpickresult"][index]
                stocktile = ( str(stocktile[0]) , str(stocktile[1]) )
                print( "package[\"stockpickresult\"]", stocktile )
                self.player.pseuddecryptedhand[int(index)] = stocktile

            play = (-1,-1)
            side = None

            board = self.game.board
            print("\nboard", board)
            print("self.player.tilesplayed", self.player.tilesplayed)

            choice = random.randint( 1, 100 )
            print("self.player.pid", self.player.pid)
            # if choice < 95 or int(self.player.pid) != 0:
            if True:
                if board != []:
                    left = board[0][0]
                    right = board[-1][1]
                    for index, tile in self.player.pseuddecryptedhand.items():
                        print("type(index)", type(index))
                        print("tile", tile, "not in self.player.tilesplayed ? ", tile not in self.player.tilesplayed)
                        if tile not in self.player.tilesplayed:
                            if tile[0] == left: # tile (5,1) 5...
                                self.player.tilesplayed.append(tile)
                                play = ( tile[1] , tile[0] )
                                side = "left"
                                print("Played tile", play, "on", side, "side")
                                print("self.player.tilesplayed", self.player.tilesplayed)
                                break
                            elif tile[1] == left: # tile (1,5) 5...
                                self.player.tilesplayed.append(tile)
                                play = tile
                                side = "left"
                                print("Played tile", play, "on", side, "side")
                                print("self.player.tilesplayed", self.player.tilesplayed)
                                break
                            elif tile[0] == right: # ...5 tile (5,1)
                                self.player.tilesplayed.append(tile)
                                play = tile
                                side = "right"
                                print("Played tile", play, "on", side, "side")
                                print("self.player.tilesplayed", self.player.tilesplayed)
                                break
                            elif tile[1] == right: # ...5 tile (1,5)
                                self.player.tilesplayed.append(tile)
                                play = ( tile[1] , tile[0] )
                                side = "right"
                                print("Played tile", play, "on", side, "side")
                                print("self.player.tilesplayed", self.player.tilesplayed)
                                break
                else:
                    print("Board is empty!")
                    index = next(iter( self.player.pseuddecryptedhand ))
                    play = self.player.pseuddecryptedhand[index]
                    self.player.tilesplayed.append(play)
                    side = "left"
            else:
                print("I ATTEMPTED TO CHEAT!")
                self.cheated = True
                index = random.randint( 0, len( self.game.fakedominoset ) - 1 )
                play = self.game.fakedominoset[index]
                if index > (len( self.game.fakedominoset ) // 2):
                    side = "left"
                else:
                    side = "right"
            
            if side != None:
                # print("Played tile", play, "on", side, "side")
                # print("self.player.tilesplayed", self.player.tilesplayed)
                pass
            else:
                print("I didn't play anything")

            if side == None and len(self.player.stock) != 0:
                print( "len(self.player.stock)", len(self.player.stock) )
                c_index = next(iter(self.player.stock))
                c_pseud = self.player.stock[c_index]
                del self.player.stock[c_index]
                #print("c_index", c_index)
                #print("c_pseud", c_pseud)
                # Generate hmac
                hmac = dh_instance.hmac_sha512( self.toByte(self.stringify_keys( { c_index: c_pseud }))
                    , self.diffiekeys.get(self.game.nplayers) ).digest()
                print("I need a stock tile")
                print( "len(self.player.stock)", len(self.player.stock) )
                package = { "message-type": "stockpick", "data": self.stringify_keys( { c_index: c_pseud } ),
                    "iam": self.player.pid, "stock": self.player.stock.copy(), "hmac": hmac }
                package = self.toByte( package )
            else:
                # Generate hmac
                print("Eu sou este jogador: ", self.player.pid)
                print("Eu sou este jogador: ", package["iam"])
                data = side
                hmac = dh_instance.hmac_sha512( self.toByte(data)
                    , self.diffiekeys.get(self.game.nplayers) ).digest()
                package = { "message-type": "play", "data": side
                    , "hmac": hmac, "iam": self.player.pid, "tile": play }
                package = self.toByte( package )

            self.socket.send( package )
        
        if( mtype == "stockpickdecrypt" ):
            # Check if packet came from server
            received_hmac = package["hmac"]
            dh_instance = self.diffieinstances.get(self.game.nplayers)
            verify_hmac = dh_instance.hmac_sha512( self.toByte( package["data"] )
                , self.diffiekeys.get(self.game.nplayers) )
            print("Did the data came from expected entity and is it ok ? --> ",self.verify(received_hmac, verify_hmac.digest()) )
            if( not self.verify(received_hmac, verify_hmac.digest()) ):
                sys.exit(1)

            print("Decrypting stock tile")
            pair = self.unstringify_keys(data.copy())
            c_index = next(iter(pair))
            c_pseud = pair[c_index]
            #print("c_index", c_index)
            #print("c_pseud", c_pseud)

            error = True
            for index_pseud, key in self.player.map.items():
                if c_pseud == index_pseud[1]:
                    self.game.writeDecypher("tmp_i.txt", c_index)
                    self.game.writeDecypher("tmp_p.txt", c_pseud)
                    c_index = self.game.aesDecypher(c_index, key)
                    c_pseud = self.game.aesDecypher(c_pseud, key)
                    #print("\nafter c_index", c_index)
                    #print("\nafter c_pseud", c_pseud)
                    error = False
                    break
            if error:
                print("\nERROR DECRYPTING A STOCK TILE\n")
            
            # Generate hmac
            hmac = dh_instance.hmac_sha512( self.toByte(self.stringify_keys( { c_index: c_pseud } ))
                , self.diffiekeys.get(self.game.nplayers) ).digest()
            package = { "message-type": "stockpickresponse", "data": self.stringify_keys( { c_index: c_pseud } )
                , "iam": self.player.pid, "hmac": hmac }
            package = self.toByte( package )
            self.socket.send( package )


        if( mtype == "update" ):
            # Check if packet came from server
            received_hmac = package["hmac"]
            dh_instance = self.diffieinstances.get(self.game.nplayers)
            verify_hmac = dh_instance.hmac_sha512( self.toByte( package["data"] )
                , self.diffiekeys.get(self.game.nplayers) )
            print("Did the data came from expected entity and is it ok ? --> ",self.verify(received_hmac, verify_hmac.digest()) )
            if( not self.verify(received_hmac, verify_hmac.digest()) ):
                sys.exit(1)

            self.player.stock = package["stock"].copy()
            print( "len(self.player.stock)", len(self.player.stock) )
            self.game.board = data
            log = []
            # print( "package[\"player\"]", type(package["player"]), "package[\"tile\"]", type(package["tile"]) )

            if package["player"] == self.player.pid:
                log = self.player.log
                # print( "self.player.log", self.player.log )

            print("")

            if package["player"] == 0:
                log = self.game.log1
            elif package["player"] == 1:
                log = self.game.log2
            elif package["player"] == 2:
                log = self.game.log3
            elif package["player"] == 3:
                log = self.game.log4
            
            if package["tile"] == (-1,-1):
                log.append("pass")
            else:
                log.append(package["tile"])
                if package["player"] != self.player.pid:

                    tile = package["tile"]
                    if int(tile[0]) < int(tile[1]):
                        correcttile = ( int(tile[1]) , int(tile[0]) )
                    else:
                        correcttile = ( int(tile[0]) , int(tile[1]) )

                    #
                    # ver se a peca atual pertence a minha mao
                    #
                    for index, ptile in self.player.pseuddecryptedhand.items():
                        if correcttile == ptile:
                            print("ERROR 1 !!! ALERT !!! THIS TILE IS IN MY HAND !!! ALERT !!!")
                            # package = { "message-type": "accuse", "data": "" }
                            # package = self.toByte( package )
                            # self.socket.send( package )
                            break
                    #
                    # ver se a peca pode ser jogada nesse lugar
                    #
                    if len( self.game.board ) > 1:
                        side = package["side"]
                        if side == "left":
                            secondtile = self.game.board[1]
                            print("tile", tile, secondtile)
                            if tile[1] != secondtile[0]:
                                print("ERROR 2 !!! ALERT !!! THIS TILE CAN'T BE PLACED HERE !!! ALERT !!!")
                        if side == "right":
                            secondlasttile = self.game.board[-2]
                            print(secondlasttile, tile, "tile")
                            if secondlasttile[1] != tile[0]:
                                print("ERROR 3 !!! ALERT !!! THIS TILE CAN'T BE PLACED HERE !!! ALERT !!!")
                        
                    
                    #
                    # verificar pecas repetidas
                    #   se for a peca atual, entao acusar o player anterior
                    #
                    cnt = 0
                    for tmptile in self.game.board:
                        if tmptile == tile or tmptile == correcttile:
                            cnt += 1
                    if cnt > 1:
                        print("ERROR 4 !!! ALERT !!! THIS TILE WAS ALREADY PLACED BEFORE !!! ALERT !!!")

            if package["player"] == 0:
                print( "self.game.log1\n", self.game.log1 )
            elif package["player"] == 1:
                print( "self.game.log2\n", self.game.log2 )
            elif package["player"] == 2:
                print( "self.game.log3\n", self.game.log3 )
            elif package["player"] == 3:
                print( "self.game.log4\n", self.game.log4 )

        if( mtype == "endgame" ):
            # Check if packet came from server
            received_hmac = package["hmac"]
            dh_instance = self.diffieinstances.get(self.game.nplayers)
            verify_hmac = dh_instance.hmac_sha512( self.toByte( package["data"] )
                , self.diffiekeys.get(self.game.nplayers) )
            print("Did the data came from expected entity and is it ok ? --> ",self.verify(received_hmac, verify_hmac.digest()) )
            if( not self.verify(received_hmac, verify_hmac.digest()) ):
                sys.exit(1)

            print( "len(self.player.hand)", len(self.player.hand) )
            # Generate hmac
            data = self.stringify_keys( self.player.hand.copy() )
            hmac = dh_instance.hmac_sha512( self.toByte(data)
                , self.diffiekeys.get(self.game.nplayers) ).digest()
            package = { "message-type": "handreveal", "data": self.stringify_keys( self.player.hand.copy() ),
                "r2": self.bitCommitR2, "iam": self.player.pid, "hmac": hmac }
            package = self.toByte( package )
            self.socket.send( package )
        
        if( mtype == "hands" ):
            # Check if packet came from server
            received_hmac = package["hmac"]
            dh_instance = self.diffieinstances.get(self.game.nplayers)
            verify_hmac = dh_instance.hmac_sha512( self.toByte( package["data"] )
                , self.diffiekeys.get(self.game.nplayers) )
            print("Did the data came from expected entity and is it ok ? --> ",self.verify(received_hmac, verify_hmac.digest()) )
            if( not self.verify(received_hmac, verify_hmac.digest()) ):
                sys.exit(1)

            self.hands = self.unstringify_valuesofvalues( data.copy() )
            print("self.hands", self.hands)
        
        if( mtype == "r2s" ):
            # Check if packet came from server
            received_hmac = package["hmac"]
            dh_instance = self.diffieinstances.get(self.game.nplayers)
            verify_hmac = dh_instance.hmac_sha512( self.toByte( package["data"] )
                , self.diffiekeys.get(self.game.nplayers) )
            print("Did the data came from expected entity and is it ok ? --> ",self.verify(received_hmac, verify_hmac.digest()) )
            if( not self.verify(received_hmac, verify_hmac.digest()) ):
                sys.exit(1)

            self.r2s = data.copy()
            print("self.r2s", self.r2s)

            print(self.bitcommits)

            validations = {}

            for id, hand in self.hands.items():
                for (name, pid) , (r1, b) in self.bitcommits.items():
                    if int(id) == int(pid) and int(id) != int(self.player.pid):
                        r2 = None
                        for tmpid, tmpr2 in self.r2s.items():
                            if int(tmpid) == int(pid):
                                r2 = tmpr2
                                break
                        if r2 == None:
                            print("ERROR 1 IN BIT COMMITMENT CHECK - CANT FIND R2 FROM THIS ID")
                        print("Player", pid, "bitcommitment -", ( b == self.checkBitCommitment(hand, int(r1), (r2)) ) )
                        print("b", b)
                        print("check", self.checkBitCommitment(hand, int(r1), (r2)))
                        validations[pid] = ( b == self.checkBitCommitment(hand, int(r1), (r2)) )

            points = 0
            for index, tile in self.player.pseuddecryptedhand.items():
                if tile not in self.player.tilesplayed:
                    print("TILE IS IN MY HAND", tile)
                    points += int(tile[0]) + int(tile[1])

            # Generate hmac
            data = validations.copy()
            hmac = dh_instance.hmac_sha512( self.toByte(data)
                , self.diffiekeys.get(self.game.nplayers) ).digest()

            package = { "message-type": "bitcommitconfirm", "data": validations.copy(), "iam": self.player.pid
                , "points": points, "hmac": hmac, "iam": package["iam"] }
            package = self.toByte( package )
            self.socket.send( package )

        return

# Maybe change generation
username = ''.join( random.choice( string.ascii_lowercase ) for i in range( 10 ) )

client = Client( '127.0.0.1', 65432, username )