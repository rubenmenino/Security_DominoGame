import socket
import threading
import random
import signal
import sys
import time
import json
from domino import Domino
from basics import *
from Diffie_v2 import DiffieHellman
import pickle

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from hashlib import blake2b
from hmac import compare_digest
from Crypto.PublicKey import RSA 
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Cipher import PKCS1_OAEP
import binascii
import hashlib
import hmac

class Server:
    def __init__( self, address, port, nplayers ):
        self.socket = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
        self.socket.bind( ( address, port ) )
        self.socket.listen( 5 )
        self.domino = None
        self.nplayers = nplayers
        self.clients = []
        self.caddress = []
        # self.domino.pseudonymMap[ PSEUD ] = TILE
        # self.domino.savepseudonyms {0: b's\xcf ... 7T%4', 1: b'\xf5   INDEX: PSEUD
        self.bitcommits = {}
        self.game = None
        #self.players = None
        self.threads = []
        self.ready = False
        self.tmpchaves = {}
        self.keymap = [] # [(0, b'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq ... ), ...]   INDEX, KEY
        self.stockpickplayer = -1
        self.didntplaycount = 0
        self.hands = {}
        self.r2s = {}
        self.numtiles = {}
        self.bitcommitsconfirms = {}
        # Diffie-Helman Variables
        self.diffieinstances = {}
        self.diffiekeys = {}
        self.shuffle = False
        self.selection = False
        self.commitment = False
        self.commitment_save = False
        self.revelation = False
        self.tdaps = False

        # Signal to exit
        signal.signal( signal.SIGINT, self.signal_handler )

        print( 'Listening on {}:{}'.format( address, port ) )

        # Accepting clients until game starts
        while len( self.clients ) != nplayers:
            csocket, caddress = self.socket.accept( )
            self.clients.append( csocket )
            self.caddress.append( caddress[1] )
            cthread = threading.Thread( target=self.handle, args=( csocket, caddress ), daemon=True )
            self.threads.append( cthread )
            cthread.start( )

        # Share keys for agreements server-client with Diffie-Helman
        for i in range(0, self.nplayers):
            print("Send public key from server to client: ", i)
            self.diffieinstances[i] = DiffieHellman( )
            serialized_public = self.diffieinstances.get(i).publicKey.public_bytes(encoding=serialization.Encoding.PEM
                , format=serialization.PublicFormat.SubjectPublicKeyInfo)
            package = { "message-type": "diffie", "data": serialized_public, "client": i }
            package = self.toByte( package )
            self.clients[i].send( package )
        # Wait for all keys to be shared
        while not self.ready:
            continue
        print("Keys have been shared!")
        # Reset variable
        self.ready = False

        # Share keys for agreements client-client with Diffie-Helman
        # Mandar pacotes as clientes a dizer para partilharem chaves entre eles (menos para o último cliente)
        for i in range(0, self.nplayers-1):
            print("Mandei pacote a dizer para mandar chaves ao cliente: ", i)
            package = { "message-type": "diffie-clients", "data": "", "client": i, "send": True, "save-back": False }
            self.clients[i].send( self.toByte( package ) )
        # Reset variable
        self.ready = False
        while not self.ready:
            continue
        # Reset variable
        self.ready = False
        time.sleep(0.5)
        
        print("A game started!\n")
        npiecesplayer = { 2:7, 3:6, 4:5 }
        self.domino = Domino( npiecesplayer.get( self.nplayers, 0 ) )

        # Pseudonymization stage
        print("Pseudonymization stage\n")
        self.domino.stagePseudonymization( )
        #print(self.domino.dominoset)

        # Randomization stage
        print("Randomization stage\n")
        dh_instance = self.diffieinstances.get(self.nplayers-1)
        hmac = dh_instance.hmac_sha512( self.toByte(self.domino.dominoset)
            , self.diffiekeys.get(self.nplayers-1) ).digest()
        package = { "message-type": "shuffle", "data": self.domino.dominoset, "firstToEncrypt": True
            , "hmac": hmac, "client": self.nplayers-1 }
        package = self.toByte( package )
        self.clients[self.nplayers-1].send( package )
        print("Shuffle by client")
        # Wait for deck to be shuffled
        while not self.shuffle:
            continue

        time.sleep(1.5)

        # Selection stage
        print("Selection stage\n")
        clientToSend = random.randint( 0, self.nplayers-1 )
        dh_instance = self.diffieinstances.get(clientToSend)
        hmac = dh_instance.hmac_sha512( self.toByte(self.domino.dominoset)
            , self.diffiekeys.get(clientToSend) ).digest()
        package = { "message-type": "selection", "data": self.domino.dominoset
            , "players-ready": False, "hmac": hmac, "client": clientToSend, "cyphered": False }
        package = self.toByte( package )
        self.clients[clientToSend].send( package )
        # Wait for all players to select their tiles
        while not self.selection:
            continue

        print("All players have full hand!")

        # Commitment stage
        print("Commitment stage\n")
        # package = { "message-type": "commitment", "save": False, "data": "", "stock": self.domino.stock }
        # package = self.toByte( package )
        # self.clients[self.nplayers-1].send( package )
        for i in range(0, self.nplayers):
            dh_instance = self.diffieinstances.get(i)
            hmac = dh_instance.hmac_sha512( self.toByte("")
                , self.diffiekeys.get(i) ).digest()
            package = { "message-type": "commitment", "save": False, "data": "", "stock": self.domino.stock
                , "hmac": hmac, "client": i, "youare": i }
            package = self.toByte( package )
            self.clients[i].send( package )
        while not self.commitment:
            continue

        # Save Commitment stage
        print("Commitment Save stage\n")
        package = { "message-type": "commitment", "save": True, "data": self.bitcommits }
        package = self.toByte( package )

        for i in range(0, self.nplayers):
            dh_instance = self.diffieinstances.get(i)
            hmac = dh_instance.hmac_sha512( self.toByte(self.bitcommits)
                , self.diffiekeys.get(i) ).digest()
            package = { "message-type": "commitment", "save": True, "data": self.bitcommits
                , "hmac": hmac, "client": i }
            package = self.toByte( package )
            self.clients[i].send( package )
        while not self.commitment_save:
            continue

        print( "Mapa dos bitcommits no server: " , self.bitcommits)

        # Revelation stage
        print("Revelation stage\n")
        dh_instance = self.diffieinstances.get(0)
        hmac = dh_instance.hmac_sha512( self.toByte("")
            , self.diffiekeys.get(0) ).digest()
        package = { "message-type": "revelation", "data": "", "firstToDecrypt": True
            , "hmac": hmac, "client": 0 }
        package = self.toByte( package )
        self.clients[0].send( package )
        while not self.revelation:
            continue
        print("Revelation stage done!")
        time.sleep(3)

        # Tile de-anonymization preparation stage
        print("Tile de-anonymization preparation stage\n")
        i = 0
        for client in self.clients:
            dh_instance = self.diffieinstances.get(i)
            hmac = dh_instance.hmac_sha512( self.toByte("")
                , self.diffiekeys.get(i) ).digest()
            package = { "message-type": "revelationdone", "data": ""
                , "hmac": hmac, "youare": i }
            package = self.toByte( package )
            client.send( package )
            i += 1
        time.sleep(3)
        print("Prev. info sent to players")

        # Tile de-anonymization preparation stage
        self.ready = False
        keys = {}
        for i in range(28):
            keys[i] = bytes()
        pseudMapEncryted = keys.copy()
        # Random player
        rplayer = random.randint( 0, self.nplayers-1 )
        # Generate hmac
        dh_instance = self.diffieinstances.get(rplayer)
        hmac = dh_instance.hmac_sha512( self.toByte(stringify_values(keys.copy()))
            , self.diffiekeys.get(rplayer) ).digest()
        package = { "message-type": "anonprep", "data": stringify_values(keys.copy()), "players-ready": False
            ,"hmac": hmac, "client": rplayer, "cyphered": False }
        package = self.toByte( package )
        self.clients[rplayer].send( package )
        while not self.tdaps:
            continue
        print("Tile deanon. prep. stage done!")

        # Tile de-anonymization stage
        #print("self.domino.pseudonymMap", self.domino.pseudonymMap)
        #pseudMapEncryted = {}
        print("\nself.savepseudonims", self.domino.savepseudonyms)
        for index1, key1 in self.keymap:
            print(".")
            print( type(index1),  type(key1))
            if key1 != "":
                pseud = self.domino.savepseudonyms[index1]
                tile = self.domino.pseudonymMap[pseud]
                pseudkey = self.domino.pseudonymKeys[pseud]
                print("pseud", pseud)
                print("tile", tile)
                print("pseudkey", pseudkey)
                print("creating pseud again", self.domino.hashPseudonym(index1, pseudkey, tile))

                tiletext = "" + str(tile[0]) + str(tile[1])

                pubkey = RSA.import_key(key1)

                encryptor = PKCS1_OAEP.new(pubkey)
                ti = encryptor.encrypt(tiletext.encode())

                encryptor = PKCS1_OAEP.new(pubkey)
                ki = encryptor.encrypt(pseudkey)

                pseudMapEncryted[index1] = (ti, ki)

        print("pseudMapEncryted", pseudMapEncryted)

        self.ready = False
        for i in range(0, self.nplayers):
            dh_instance = self.diffieinstances.get(i)
            hmac = dh_instance.hmac_sha512( self.toByte(self.stringify_tuples( pseudMapEncryted.copy() ))
                , self.diffiekeys.get(i) ).digest()
            package = { "message-type": "deanon", "data": self.stringify_tuples( pseudMapEncryted.copy() )
                , "hmac": hmac, "client": i }
            package = self.toByte( package )
            self.clients[i].send( package )

        # GAME ON

        self.domino.nplayers = self.nplayers

        # Random player order
        self.domino.playerorder = []
        for i in range(self.nplayers):
            print(i)
            self.domino.playerorder.append(i)

            self.numtiles[i] = self.domino.npiecesplayer
            print("Player", i, "has", self.numtiles[i], "tiles")
        random.shuffle(self.domino.playerorder)
        
        print(self.domino.playerorder)

        self.domino.nextplayer = self.domino.updateTurn()

        # Generate hmac
        dh_instance = self.diffieinstances.get(self.domino.nextplayer)
        hmac = dh_instance.hmac_sha512( self.toByte(self.domino.board)
            , self.diffiekeys.get(self.domino.nextplayer) ).digest()

        package = { "message-type": "yourturn", "data": self.domino.board
            , "hmac": hmac, "iam": self.domino.nextplayer }
        package = self.toByte( package )
        self.clients[ self.domino.nextplayer ].send( package )

        print("playerorder", self.domino.playerorder)
        print("board", self.domino.board)

        # Stock use
        while True:
            continue
        
    def sendall( self, package ):
        for csocket in self.clients:
            csocket.send( package )
        
        time.sleep( 0.2 )

    def handle( self, csocket, address ):
        print( 'Accepted connection from {}:{}'.format( address[0], address[1] ) )

        try:
            while True:
                package = b''
                while True:
                    # Receive packages from client
                    part = csocket.recv( 4096 )
                    package += part
                    if len(part) < 4096:
                        break

                # print("package", package)
                package = self.toObject( package )
                mtype = package["message-type"]
                data = package["data"]
                
                if( mtype == "join" ):
                    package = { "message-type": "join", "data": "200", "nplayers": self.nplayers }
                    # Send byte package to client
                    csocket.send( self.toByte( package ) )

                if( mtype == "diffie" ):
                    client = package["client"]
                    # Save public keys received from clients from agreement server-client
                    loaded_public_key = serialization.load_pem_public_key(package["data"])
                    print("Estou a receber do agreement server-client a chave do cliente {} a chave pública: {}!"
                        .format(client, loaded_public_key))
                    self.diffiekeys[client] = loaded_public_key

                    # decipheredMessage = self.diffieinstances.get(client).decrypt(self.diffiekeys.get(client)
                    # , package["cipheredMessage"], package["iv"])
                    # shared_key = self.diffieinstances.get(client).shared_key( self.diffiekeys.get(client) )
                    # print("shared key: ", shared_key)
                    # print( "Texto decifrado", decipheredMessage )

                    self.ready = True
                
                if( mtype == "diffie-clients" ):
                    client = package["client"]
                    package = { "message-type": "diffie-clients", "data": package["data"]
                        , "client": package["client"], "send": False, "from": package["from"], "save-back": package["save-back"] }
                    self.clients[client].send( self.toByte( package ) )
                    # print("from: ", package["from"])
                    # print("client: ", package["client"])
                    if( package["from"] == self.nplayers-1 and package["client"] == self.nplayers-2):
                        print("print me once")
                        self.ready = True
                
                if( mtype == "shuffle" ):
                    if( self.nplayers != 1 ):
                        self.nplayers -= 1 
                        # Verify hmac from client
                        dh_instance = self.diffieinstances.get(package["client"])
                        verify_hmac = dh_instance.hmac_sha512( self.toByte( package["data"] )
                            , self.diffiekeys.get(package["client"]) )
                        # print("Received hmac: ", package["hmac"])
                        # print("Generated hmac: ", verify_hmac.digest())
                        print("Did the data came from expected entity and is it ok ? --> ",self.verify(package["hmac"], verify_hmac.digest()) )
                        if( not self.verify(package["hmac"], verify_hmac.digest()) ):
                            sys.exit(1)
                        # Create hmac
                        dh_instance = self.diffieinstances.get(self.nplayers-1)
                        hmac = dh_instance.hmac_sha512( self.toByte(data)
                            , self.diffiekeys.get(self.nplayers-1) ).digest()
                        # where the deck data is going to be what received from previous player
                        # print("Domino set shuffled: ", data)
                        package = { "message-type": "shuffle", "data": data, "firstToEncrypt": False
                            , "hmac": hmac, "client": self.nplayers-1 }
                        self.clients[self.nplayers-1].send( self.toByte( package ) )
                        print("Shuffle by client")

                    else:
                        # Nao pode ser guardado assim, temos de dar unstringify, tal como o cliente faz
                        # self.domino.dominoset = data.copy( )
                        self.domino.dominoset = self.unstringify_keys( data.copy() )
                        #print("DECK SHUFFLED", self.domino.dominoset)
                        self.nplayers = len( self.clients )
                        self.shuffle = True
                        self.ready = True
                        print("Deck finished shuffling by players!\n")

                if( mtype == "selection" ):
                    ready = package["players-ready"]
                    # Players picked up all tiles
                    print("player preformed a select action!")
                    # print("Variable ready status, ", self.ready)
                    # print(data)
                    # Verify hmac from client
                    dh_instance = self.diffieinstances.get(package["from"])
                    verify_hmac = dh_instance.hmac_sha512( self.toByte( data )
                        , self.diffiekeys.get(package["from"]) )
                    # print("Received hmac: ", package["hmac"])
                    # print("Generated hmac: ", verify_hmac.digest())
                    print("Did the data came from expected entity and is it ok ? --> ",self.verify(package["hmac"], verify_hmac.digest()) )
                    if( not self.verify(package["hmac"], verify_hmac.digest()) ):
                        sys.exit(1)
                    # Verificar de alguma maneira se todos os jogadores têm as peças minimas ?
                    # COMPLETE
                    # ANY PLAYER SEND A SINGAL THROW JSON PARAMETER
                    # Create hmac
                    dh_instance = self.diffieinstances.get(package["client"])
                    hmac = dh_instance.hmac_sha512( self.toByte(data)
                        , self.diffiekeys.get(package["client"]) ).digest()
                    if( ready ):
                        self.selection = True
                        # Save stock that didn't get picked by players
                        #print("DECK SELECTED", data.copy() )
                        self.domino.stock = data.copy()
                        #print(self.domino.stock)
                    
                    # Redirect to the player that the player choose
                    else:
                        package = { "message-type": "selection", "data": data, "players-ready": False
                            , "hmac": hmac , "client": package["client"], "from": package["from"], "cyphered": package["cyphered"]
                            , "iv": package["iv"] }
                        self.clients[package["client"]].send( self.toByte( package ) )  

                if( mtype == "commitment" ):
                    # Verify hmac from client
                    dh_instance = self.diffieinstances.get(package["client"])
                    verify_hmac = dh_instance.hmac_sha512( self.toByte( package["data"] )
                        , self.diffiekeys.get(package["client"]) )
                    print("Did the data came from expected entity and is it ok ? --> ",self.verify(package["hmac"], verify_hmac.digest()) )
                    if( not self.verify(package["hmac"], verify_hmac.digest()) ):
                        sys.exit(1)
                    if( not package["save"] ):
                        self.bitcommits.update( { (package["username"],package["iam"]): [ data[0], data[1] ] } )
                        if len( self.bitcommits ) == self.nplayers:
                            self.commitment = True
                    else:
                        self.commitment_save = True
                
                if( mtype == "revelation" ):
                    # Verify hmac from client
                    dh_instance = self.diffieinstances.get(package["client"])
                    verify_hmac = dh_instance.hmac_sha512( self.toByte( package["data"] )
                        , self.diffiekeys.get(package["client"]) )
                    print("Did the data came from expected entity and is it ok ? --> ",self.verify(package["hmac"], verify_hmac.digest()) )
                    if( not self.verify(package["hmac"], verify_hmac.digest()) ):
                        sys.exit(1)
                    print("Recived", len(data.copy()), "keys from client: ", package["client"])
                    self.tmpchaves = data.copy()
                    # print("tmpchaves:", self.tmpchaves)
                    actualclient = package["client"]

                    nextclient = actualclient + 1

                    # Save keys and send to next client
                    # WARNING: meter código que não sei bem o que é, mas temos de criar 
                    # uma variável global aqui no server que vai guardando as chaves
                    data = self.tmpchaves.copy()

                    print("Sending keys from", actualclient, "to everyone else")
                    i = 0
                    for client in self.clients:
                        # print("is this client,", i, "???")
                        # actualclient e' o gajo que mandou estas chaves
                        if i != actualclient:
                            print("iterating client", i, "keys SENT")
                            # Create hmac
                            dh_instance = self.diffieinstances.get(i)
                            hmac = dh_instance.hmac_sha512( self.toByte(data)
                                , self.diffiekeys.get(i) ).digest()
                            # mandar as chaves deste bro para os outros manfios basicamente
                            package = { "message-type": "revelation-save", "data": data
                                , "hmac": hmac, "client": actualclient }
                            client.send( self.toByte( package ) )
                        else:
                            print("iterating client", i, "keys NOT sent")
                        i += 1

                    if( actualclient != self.nplayers-1 ):
                        # Create hmac
                        dh_instance = self.diffieinstances.get(nextclient)
                        hmac = dh_instance.hmac_sha512( self.toByte("")
                            , self.diffiekeys.get(nextclient) ).digest()
                        # Next client
                        package = { "message-type": "revelation", "data": "", "firstToDecrypt": False
                            , "hmac": hmac, "client": nextclient }
                        self.clients[nextclient].send( self.toByte( package ) )
                    else:
                        # Guardar últimas chaves recebidas no lado do servidor
                        # WARNING: guardar numa últimas chaves recebidas do último cliente
                        # WARNING: acho que podemos tirar isto que não há problema, 
                        # mas está com problemas de concorrência a variável self.ready
                        # time.sleep(2)
                        self.revelation = True
                        print("Randomizaton stage keys were saved by server sucessfully!\n")

                if( mtype == "anonprep" ):
                    # Verify hmac from client
                    dh_instance = self.diffieinstances.get(package["from"])
                    verify_hmac = dh_instance.hmac_sha512( self.toByte( package["data"] )
                        , self.diffiekeys.get(package["from"]) )
                    print("Did the data came from expected entity and is it ok ? --> ",self.verify(package["hmac"], verify_hmac.digest()) )
                    if( not self.verify(package["hmac"], verify_hmac.digest()) ):
                        sys.exit(1)

                    #print("package[\"players-ready\"]", package["players-ready"])
                    done = package["players-ready"]
                    if done == True:
                        self.keymap = data.copy()
                        print("STAGE DONE")
                        self.tdaps = True
                        # print("KEY MAP", data.copy())
                        print("KEY MAP", self.keymap)
                    else:
                        # Send to the client choosed by the player before
                        next_player = package["client"]
                        # Create hmac
                        dh_instance = self.diffieinstances.get(next_player)
                        hmac = dh_instance.hmac_sha512( self.toByte(data)
                            , self.diffiekeys.get(next_player) ).digest()
                        package = { "message-type": "anonprep", "data": data, "players-ready": False
                            , "hmac": hmac, "client": next_player, "from": package["from"], "cyphered": True, "iv": package["iv"] }
                        package = self.toByte( package )
                        self.clients[next_player].send( package )

                if( mtype == "play" ):
                    print("eu recebi pacote deste jogador: ", package["iam"])
                    # Verify hmac from client
                    dh_instance = self.diffieinstances.get(package["iam"])
                    verify_hmac = dh_instance.hmac_sha512( self.toByte( package["data"] )
                        , self.diffiekeys.get(package["iam"]) )
                    print("Did the data came from expected entity and is it ok ? --> ",self.verify(package["hmac"], verify_hmac.digest()) )
                    if( not self.verify(package["hmac"], verify_hmac.digest()) ):
                        sys.exit(1)

                    tile = package["tile"]
                    side = package["data"]
                    if tile != (-1,-1) and side != None:
                        self.domino.placePiece(side, tile)
                        self.didntplaycount = 0
                        self.numtiles[self.domino.nextplayer] -= 1
                    else:
                        print("Player didn't play!!!")
                        self.didntplaycount += 1
                    
                    print("Player", self.domino.nextplayer, "has", self.numtiles[self.domino.nextplayer], "tiles")

                    for i in range(0, self.nplayers):
                        # Create hmac
                        dh_instance = self.diffieinstances.get(i)
                        hmac = dh_instance.hmac_sha512( self.toByte(self.domino.board)
                            , self.diffiekeys.get(i) ).digest()
                        package = { "message-type": "update", "data": self.domino.board, "player": self.domino.nextplayer,
                            "tile": tile, "side": side, "stock": self.domino.stock.copy(), "hmac": hmac, "iam": i }
                        package = self.toByte( package )
                        self.clients[i].send( package )

                    time.sleep(0.5)

                    if self.didntplaycount == self.nplayers or self.numtiles[self.domino.nextplayer] == 0:
                        # end game, show hands, confirm bit commitments, show points
                        print("GAME ENDED")
                        if self.didntplaycount == self.nplayers:
                            print("!!! No more pieces can be played !!!")
                        elif self.numtiles[self.domino.nextplayer] == 0:
                            print("!!! Player", self.domino.nextplayer, "reached", self.numtiles[self.domino.nextplayer], "tiles !!!")
                        for i in range(0, self.nplayers):
                            # Create hmac
                            dh_instance = self.diffieinstances.get(i)
                            hmac = dh_instance.hmac_sha512( self.toByte("")
                                , self.diffiekeys.get(i) ).digest()
                            package = { "message-type": "endgame", "data": "", "hmac": hmac, "iam": i }
                            package = self.toByte( package )
                            self.clients[i].send( package )

                    else:
                        self.domino.nextplayer = self.domino.updateTurn()
                        # Create hmac
                        dh_instance = self.diffieinstances.get(self.domino.nextplayer)
                        hmac = dh_instance.hmac_sha512( self.toByte(self.domino.board)
                            , self.diffiekeys.get(self.domino.nextplayer) ).digest()
                        package = { "message-type": "yourturn", "data": self.domino.board, "hmac": hmac, "iam": self.domino.nextplayer }
                        package = self.toByte( package )
                        self.clients[ self.domino.nextplayer ].send( package )

                if( mtype == "stockpick" ):
                    # Verify hmac from client
                    dh_instance = self.diffieinstances.get(package["iam"])
                    verify_hmac = dh_instance.hmac_sha512( self.toByte( package["data"] )
                        , self.diffiekeys.get(package["iam"]) )
                    print("Did the data came from expected entity and is it ok ? --> ",self.verify(package["hmac"], verify_hmac.digest()) )
                    if( not self.verify(package["hmac"], verify_hmac.digest()) ):
                        sys.exit(1)

                    print( "len(self.domino.stock)", len(self.domino.stock) )
                    self.domino.stock = package["stock"].copy()
                    print( "len(self.domino.stock)", len(self.domino.stock) )
                    who = package["iam"]
                    self.stockpickplayer = who
                    print("Player", who, "asked for a stock tile")
                    print("Sending stock decryption request to player 0")
                    # Create hmac
                    dh_instance = self.diffieinstances.get(0)
                    hmac = dh_instance.hmac_sha512( self.toByte(data)
                        , self.diffiekeys.get(0) ).digest()
                    package = { "message-type": "stockpickdecrypt", "data": data, "hmac": hmac, "iam": 0 }
                    package = self.toByte( package )
                    self.clients[0].send( package )

                if( mtype == "stockpickresponse" ):
                    who = package["iam"]
                    # Verify hmac from client
                    dh_instance = self.diffieinstances.get(package["iam"])
                    verify_hmac = dh_instance.hmac_sha512( self.toByte( package["data"] )
                        , self.diffiekeys.get(package["iam"]) )
                    print("Did the data came from expected entity and is it ok ? --> ",self.verify(package["hmac"], verify_hmac.digest()) )
                    if( not self.verify(package["hmac"], verify_hmac.digest()) ):
                        sys.exit(1)

                    if who != self.nplayers-1:
                        print("Sending stock decryption request to player", who+1)
                        # Create hmac
                        dh_instance = self.diffieinstances.get(who+1)
                        hmac = dh_instance.hmac_sha512( self.toByte(data)
                            , self.diffiekeys.get(who+1) ).digest()
                        package = { "message-type": "stockpickdecrypt", "data": data, "hmac": hmac, "iam": who+1 }
                        package = self.toByte( package )
                        self.clients[who+1].send( package )
                    else:
                        print("Deanonymizing stock picked tile")
                        pair = self.unstringify_keys(data.copy())
                        index = next(iter(pair))
                        pseud = pair[index]
                        index = index.decode()
                        pseud = pseud.decode()
                        print("index", index)
                        print("pseud", pseud)
                        error = True
                        for tmppseud, tile in self.domino.pseudonymMap.items():
                            if pseud == str(tmppseud):
                                print("Sending stock tile", tile, "to player", self.stockpickplayer)
                                self.numtiles[self.stockpickplayer] += 1
                                error = False
                                # Create hmac
                                dh_instance = self.diffieinstances.get(self.stockpickplayer)
                                hmac = dh_instance.hmac_sha512( self.toByte(self.domino.board)
                                    , self.diffiekeys.get(self.stockpickplayer) ).digest()
                                package = { "message-type": "yourturn", "data": self.domino.board,
                                    "stockpickresult": { index: tile }, "hmac": hmac, "iam": self.stockpickplayer }
                                package = self.toByte( package )
                                self.clients[self.stockpickplayer].send( package )
                                break
                        if error:
                            print("\nERROR DECRYPTING A STOCK TILE\n")

                if( mtype == "handreveal" ):
                    who = package["iam"]
                    # Verify hmac from client
                    dh_instance = self.diffieinstances.get(package["iam"])
                    verify_hmac = dh_instance.hmac_sha512( self.toByte( package["data"] )
                        , self.diffiekeys.get(package["iam"]) )
                    print("Did the data came from expected entity and is it ok ? --> ",self.verify(package["hmac"], verify_hmac.digest()) )
                    if( not self.verify(package["hmac"], verify_hmac.digest()) ):
                        sys.exit(1)

                    self.hands[who] = self.unstringify_keys( data.copy() )
                    self.r2s[who] = package["r2"]

                    if len(self.hands) == self.nplayers:
                        for i in range(0, self.nplayers):
                            # Create hmac
                            dh_instance = self.diffieinstances.get(i)
                            data = self.stringify_valuesofvalues( self.hands.copy() )
                            hmac = dh_instance.hmac_sha512( self.toByte(data)
                                , self.diffiekeys.get(i) ).digest()
                                
                            package = { "message-type": "hands", "data": self.stringify_valuesofvalues( self.hands.copy() )
                                , "hmac": hmac, "iam": i }
                            package = self.toByte( package )
                            self.clients[i].send( package )
                        time.sleep(1)
                        for i in range(0, self.nplayers):
                            # Create hmac
                            dh_instance = self.diffieinstances.get(i)
                            data = self.r2s.copy()
                            hmac = dh_instance.hmac_sha512( self.toByte(data)
                                , self.diffiekeys.get(i) ).digest()

                            package = { "message-type": "r2s", "data": self.r2s.copy()
                                , "hmac": hmac, "iam": i }
                            package = self.toByte( package )
                            self.clients[i].send( package )
                        time.sleep(1)

                        print("self.bitcommits", self.bitcommits)

                if( mtype == "bitcommitconfirm" ):
                    who = package["iam"]
                    points = package["points"]
                    # Verify hmac from client
                    dh_instance = self.diffieinstances.get(package["iam"])
                    verify_hmac = dh_instance.hmac_sha512( self.toByte( package["data"] )
                        , self.diffiekeys.get(package["iam"]) )
                    print("Did the data came from expected entity and is it ok ? --> ",self.verify(package["hmac"], verify_hmac.digest()) )
                    if( not self.verify(package["hmac"], verify_hmac.digest()) ):
                        sys.exit(1)

                    self.bitcommitsconfirms[who] = ( points , data.copy() )
                    
                    if len(self.bitcommitsconfirms) == self.nplayers:
                        error = False
                        for pid, validation in self.bitcommitsconfirms.items():
                            print("valid?", validation[1])
                            if not validation[1]:
                                error = True
                                break
                        if error:
                            print("GAME ABORTED, BIT COMMITMENTS WHERE NOT VALIDATED")
                        else:
                            print("GAME WAS A SUCCESS")
                            playerpoints = {}
                            for pid, validation in self.bitcommitsconfirms.items():
                                playerpoints[pid] = validation[0]

                            print("playerpoints", playerpoints)

                            winner = -1
                            for pid, points in playerpoints.items():
                                if winner == -1:
                                    winner = pid
                                else:
                                    if playerpoints[winner] > playerpoints[pid]:
                                        winner = pid
                            print("WINNER IS", winner)
                
                
        except ( socket.timeout, socket.error ):
            print('Client {} error, system exit!\n'.format(address))
        finally:
            csocket.close()

    def checkBitCommitment(self, hand, r1, r2):
        
        hashFunction = hashlib.sha256()

        for key, value in hand.items():
            hashFunction.update(key)
            hashFunction.update(value)

        hashFunction.update(bytes(int(r1)))
        hashFunction.update(bytes(int(r2)))

        return hashFunction.hexdigest()

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

    def toByte( self, package ):
        # package = json.dumps( package, indent=4 )
        # package = package.encode( )
        package = pickle.dumps( package )
        return package

    def toObject( self, package ):
        # package = package.decode( )
        # package = json.loads( package )
        package = pickle.loads( package )
        return package

    def verify(self, hash1, hash2):
        return compare_digest(hash1, hash2)

    def hmac_sha512(self, msg, key):
        return hmac.new(msg, key, hashlib.sha512)
    
    def signal_handler(self, signal, frame):
        print('\nDone!')

        self.socket.shutdown( socket.SHUT_RDWR )
        self.socket.close( )
        sys.exit( 0 )

table_manager = Server( '127.0.0.1', 65432, 3 )
