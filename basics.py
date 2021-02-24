import random
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import padding

import os

class Player:
    id = 0
    hand = []

    def __init__(self, id):
        self.id = id

class GameEngine:
    playerlist = []
    pieces_perplayer = 0
    dominoset = [(6,6),(6,5),(6,4),(6,3),(6,2),(6,1),(6,0),
                (5,5),(5,4),(5,3),(5,2),(5,1),(5,0),
                (4,4),(4,3),(4,2),(4,1),(4,0),
                (3,3),(3,2),(3,1),(3,0),
                (2,2),(2,1),(2,0),
                (1,1),(1,0),
                (0,0)]
    stock = []
    board = []
    playerorder = []
    currentplayerid = 0
    pseudonymMap = {}

    # randomization maps // um para cada jogador // estes mapas pertencem apenas aos jogadores xddd

    map1 = {}
    map2 = {}
    map3 = {}
    map4 = {}

    def __init__(self, playerlist, pieces_perplayer):
        # example -> playerlist = [Player(id=1), Player(id=2), Player(id=3), Player(id=4)]
        self.playerlist = playerlist
        self.pieces_perplayer = pieces_perplayer
        random.shuffle(self.dominoset)

###########################################################################################
# codigo comum maybe
###########################################################################################

    def hashPseudonym(self, i, key, tile):
        digest = hashes.Hash(hashes.SHA256(), default_backend() )
        # for i in range (0,len(plainTail)):    # {
        _digest = digest.copy()
        # key = secrets.token_bytes(32)
        _digest.update(bytes(i))
        _digest.update(key)
        _digest.update(bytes(tile))
        p = _digest.finalize()                  # }
        # digest.finalize()
        return p

    def aesCypher(self, content, key, firstencription):
        
        nonce = secrets.token_bytes(12)

        if (firstencription == True):
            ciphertext = nonce + AESGCM(key).encrypt(nonce, bytes(str(content), encoding='utf-8'), b"")
        else:
            ciphertext = nonce + AESGCM(key).encrypt(nonce, content, b"")
        
        return ciphertext
    
    def aesDecypher(self, content, key):
        # print("content[:12]", content[:12])
        # print("content[12:]", content[12:])
        return AESGCM(key).decrypt(content[:12], content[12:], b"")

    def genPwdKey(self, pwd):
        salt = b'\r00'
        kdf = PBKDF2HMAC(hashes.SHA1(), 16, salt, 1000, default_backend())
        return kdf.derive(bytes(pwd, 'UTF-8'))

    def gen28keys(self):
        pwds = [] # passwords
        keys = []

        duplicates = True

        while(duplicates):
            pwds = random.sample(range(100,999),28)
            # teste para 2 chaves duplicadas
            # pwds = [113, 545, 802, 101, 393, 385, 720, 729, 873, 660, 813, 762, 259, 186, 186, 430, 909, 769, 946, 686, 665, 549, 747, 355, 898, 731, 787, 571]
            duplicates = any(pwds.count(element) > 1 for element in pwds)
            # print("duplicates? ")
            # print(bool(duplicates))
            # print("\npwds")
            # print(pwds)

        for pwd in pwds:
            keys.append( self.genPwdKey(str(pwd)) )
        
        # print(keys)

        # keys é o conjunto das 28 chaves
        return keys
        # old method
        # return [113, 545, 802, 101, 393, 385, 720, 729, 873, 660, 813, 762, 259, 186, 186, 430, 909, 769, 946, 686, 665, 549, 747, 355, 898, 731, 787, 571]

###########################################################################################
# codigo servidor
###########################################################################################

    def stagePseudonymization(self):
        # print("eu to vivo\n")
        keyset = self.gen28keys()

        for i in range(len(self.dominoset)):
            tile = self.dominoset[i]
            key = keyset[i]
            # GERAR PSEUDONIMOOOOOOO
            # newvalue = self.pseudonymize(i, key, tile)
            newvalue = self.hashPseudonym(i, key, tile)
            self.dominoset[i] = i,newvalue # este e o deck que vai ser enviado para a fase de randomizacao
            # self.pseudonymMap[str(newvalue)] = tile
            self.pseudonymMap[newvalue] = tile
        
        self.dominoset = dict(self.dominoset)

    def pseudonymize(self, i, key, tile):
        # funcao toda mamada para criar pseudonimo
        # mas por agora apenas uma ceninha simples
        return i*2 + 1*1000 + tile[0]*10 + tile[1]*100

###########################################################################################
# codigo cliente
###########################################################################################

    def stageRandomization(self, map, firstencription):
        # print("eu to vivo\n")
        # keyset = self.gen28keys()

        dominoset_view = self.dominoset.values()
        value_iterator = iter(dominoset_view)

        newdominoset = {}

        for index, pseudonym in self.dominoset.items():
            # key = keyset.pop()
            key = secrets.token_bytes(32)
            newindex = self.aesCypher( index, key, firstencription )
            newpseud = self.aesCypher( pseudonym, key, firstencription )
            newdominoset[newindex] = newpseud
            map[(newindex,newpseud)] = key

        # print("\nmapa:")
        # print(map)

        # print("\nencriptado:")
        # print(newdominoset)
        newdominoset = list(newdominoset.items())
        random.shuffle(newdominoset)
        newdominoset = dict(newdominoset)
        # print("\nshuffled:")
        # print(newdominoset)

        self.dominoset = newdominoset.copy()

###########################################################################################
# codigo palha
###########################################################################################
    
    def assignPiece(self, piece, playerid):
        # example -> piece = (5,2), playerid = 1
        for player in self.playerlist:
            if player.id == playerid:
                player.hand.append(piece)
    
    def execute_draw_phase(self):
        playercount = len(self.playerlist)

        for i in range(playercount):
            player_highestdouble = -1
            highestdouble = (-1,-1)
            player_highestdomino = -1
            highestdomino = (-1,-1)

            for player in self.playerlist:
                if not (player.id in playerorder):
                    for piece in player.hand:
                        if isDouble(piece):
                            if piece == compareDoubles(piece, highestdouble):
                                highestdouble = piece
                                player_highestdouble = player.id
                        else:
                            if piece == compareDominos(piece, highestdomino):
                                highestdomino = piece
                                player_highestdomino = player.id
        
            if highestdouble != (-1,-1):
                playerorder.append(player_highestdouble)
            elif highestdomino != (-1,-1):
                playerorder.append(player_highestdomino)
        
        self.currentplayerid = playerorder[0]

    def placePiece(self, side, piece):
        if side=="left":
            self.board.insert(0, piece)
        else:
            self.board.append(piece)
        print("\n\n----------------------------------------------------------\n\nBoard",self.board,"\n\n")
        self.updateTurn()

    def updateTurn(self):
        nextplayer = self.playerorder.pop()
        self.playerorder.insert(0, nextplayer)
    

###########################################################################################
# funcoes auxiliares
###########################################################################################

def pieceSum(piece):
    # returns the number of dots in a piece
    return piece[0] + piece[1]

def compareDominos(piece1, piece2):
    # returns the domino with most dots
    # if they have the same number of dots -> (5,0) better than (4,1)
    if pieceSum(piece1) > pieceSum(piece2):
        return piece1
    elif pieceSum(piece1) < pieceSum(piece2):
        return piece2
    else:
        if piece1[0] > piece2[0]:
            return piece1
        return piece2

def compareDoubles(piece1, piece2):
    # returns highest double
    if piece1[0] > piece2[0]:
        return piece1
    return piece2

def isDouble(piece):
    # checks if a piece is a double
    if piece[0] == piece[1]:
        return True
    return False

###########################################################################################
# main
###########################################################################################

def autoRun():

    player1 = Player(id=1)
    player2 = Player(id=2)
    player3 = Player(id=3)
    player4 = Player(id=4)

    game = GameEngine([player1,player2,player3,player4],5)

    print(game.dominoset)

    game.stagePseudonymization()

    print("\nCRIACAO DE PSEUDONIMOS")
    print(game.dominoset)

    game.stageRandomization(game.map1, True)
    # print("\nRANDOMIZACAO JOGADOR 1")
    # print(game.dominoset)

    game.stageRandomization(game.map2, False)
    # print("\nRANDOMIZACAO JOGADOR 2")
    # print(game.dominoset)

    game.stageRandomization(game.map3, False)
    # print("\nRANDOMIZACAO JOGADOR 3")
    # print(game.dominoset)

    game.stageRandomization(game.map4, False)
    # print("\nRANDOMIZACAO JOGADOR 4")
    # print(game.dominoset)


    print("quero decriptar este tuplo")
    keyword = next(iter(game.dominoset))
    print("index --->>>\n", keyword)
    print("pseud --->>>\n", game.dominoset[keyword])

    # print(game.map4)

    def writeDecypher(outfile, content):
        fout = open(outfile, 'wb')
        fout.write(content)
        fout.close()
    def readDecypher(outfile):
        fout = open(outfile, 'rb')
        data = fout.read()
        #print("\n\nDATAAAAAAAAAAAAAA")
        #print(data)
        fout.close()
        return data

    i = keyword
    ti = game.dominoset[keyword]

    oldi = i
    oldti = ti

    testdict = {}

    testdict[i] = ti
    print("TESTDICT INIT ", testdict)

    testdict2 = stringify_keys(testdict)
    print("STRINGIFIED ", testdict2)

    testdict3 = unstringify_keys(testdict2)
    print("UN-STRINGIFIED ", testdict3)

    i = next(iter(testdict3))
    ti = testdict3[i]

    print(i==oldi, "i", i)
    print(ti==oldti, "ti", ti)

    for c, key in game.map4.items():
        index = c[0]
        pseud = c[1]
        if(index == i and pseud == ti):
            print("\n\nENCONTREI O TUPLO QUE EU QUERO DECIFRAR")
            print(c)
            print("\nA CHAVE CORRESPONDENTE")
            print(key)
            writeDecypher("tmp_i.txt", index)
            writeDecypher("tmp_p.txt", pseud)

            i = game.aesDecypher(index, key)
            # i = game.aesDecypher("tmp_i.txt", key)
            # decipherout.txt -> i
            # i = readDecypher("decipherout.txt")
            
            ti = game.aesDecypher(pseud, key)
            # ti = game.aesDecypher("tmp_p.txt", key)
            # decipherout.txt -> ti
            #ti = readDecypher("decipherout.txt")

            print("\nINDEX QUE EU QUERO ENCONTRAR NO MAPA 3")
            print(i)
            print("PSEUDONIMO TAL TAL TAL")
            print(ti)
            break
    
    # print("\n\nMAPAAAAA\n")
    # print(game.map3)

    for c, key in game.map3.items():
        index = c[0]
        pseud = c[1]
        if(index == i and pseud == ti):
            print("c",c,"key",key)
            writeDecypher("tmp_i.txt", index)
            writeDecypher("tmp_p.txt", pseud)

            i = game.aesDecypher(index, key)
            # i = game.aesDecypher("tmp_i.txt", key)
            # decipherout.txt -> i
            # i = readDecypher("decipherout.txt")
            
            ti = game.aesDecypher(pseud, key)
            # ti = game.aesDecypher("tmp_p.txt", key)
            # decipherout.txt -> ti
            #ti = readDecypher("decipherout.txt")

            print("index",i,"pseud",ti)
            break

    for c, key in game.map2.items():
        index = c[0]
        pseud = c[1]
        if(index == i and pseud == ti):
            print("c",c,"key",key)
            writeDecypher("tmp_i.txt", index)
            writeDecypher("tmp_p.txt", pseud)

            i = game.aesDecypher(index, key)
            # i = game.aesDecypher("tmp_i.txt", key)
            # decipherout.txt -> i
            # i = readDecypher("decipherout.txt")
            
            ti = game.aesDecypher(pseud, key)
            # ti = game.aesDecypher("tmp_p.txt", key)
            # decipherout.txt -> ti
            #ti = readDecypher("decipherout.txt")

            print("index",i,"pseud",ti)
            break

    for c, key in game.map1.items():
        index = c[0]
        pseud = c[1]
        if(index == i and pseud == ti):
            print("c",c,"key",key)
            writeDecypher("tmp_i.txt", index)
            writeDecypher("tmp_p.txt", pseud)

            i = game.aesDecypher(index, key).decode()
            # i = game.aesDecypher("tmp_i.txt", key)
            # decipherout.txt -> i
            # i = readDecypher("decipherout.txt")
            
            ti = game.aesDecypher(pseud, key).decode()
            # ti = game.aesDecypher("tmp_p.txt", key)
            # decipherout.txt -> ti
            #ti = readDecypher("decipherout.txt")

            print("index",i,"pseud",ti)
            break
    
    print("\n\n", game.pseudonymMap, "\n\n")

    # print("pseudonimo", ti, "corresponde ao tile", game.pseudonymMap[ti])
    # ti e' o resultado da decifra. e' do tipo string
    # nao posso fazer essa linha pq as keys desse dict (pseudonimos) ja nao sao guardadas como strings
    for pseud, tile in game.pseudonymMap.items():
        if ti == str(pseud):
            print("pseudonimo", pseud, "corresponde ao tile", tile)
    

    ############################################################################

    # testdict = {}
    # for i in range(28):
    #     if i % 2 == 0:
    #         testdict[i] = secrets.token_bytes(32)
    #     else:
    #         testdict[i] = bytes()

    # testdict[i] = ti
    # print("TESTDICT INIT ", testdict)

    # testdict2 = stringify_values(testdict)
    # print("STRINGIFIED ", testdict2)

    # testdict3 = unstringify_values(testdict2)
    # print("UN-STRINGIFIED ", testdict3)

    ############################################################################



    # print("\nciphering text \"123\"")

    # key1 = secrets.token_bytes(32)
    # bytes1 = game.aesCypher(123, key1, True)
    # print("bytes1", bytes1)
    
    # key2 = secrets.token_bytes(32)
    # bytes2 = game.aesCypher(bytes1, key2, False)
    # print("bytes2", bytes2)

    # print("\ndecyphering bytes2")
    # bytes1 = game.aesDecypher(bytes2, key2)
    # print("bytes1", bytes1)

    # print("\ndecyphering bytes1")
    # text = game.aesDecypher(bytes1, key1).decode()
    # print("text", text)

    ############################################################################





    ############################################################################

    # game.assignPiece((6,0),1)
    # game.assignPiece((5,4),1)
    # game.assignPiece((4,2),1)
    # game.assignPiece((3,0),1)
    # game.assignPiece((6,5),1)
    # print("player1",player1.hand)

    # player2.hand = [(5,0),(4,3),(6,3),(5,3),(4,1)]
    # player3.hand = [(4,0),(3,2),(2,0),(6,4),(5,2)]
    # player4.hand = [(3,1),(2,1),(5,1),(1,0),(6,2)]
    # print("player2",player2.hand)
    # print("player3",player3.hand)
    # print("player4",player4.hand)

    # game.execute_draw_phase()
    # print("player turn order",game.playerorder)

    # while(True):
    #     for player in game.playerlist:
    #         if player.id == game.currentplayerid:
    #             currentplayer = player
        
    #     print("Hand",currentplayer.hand)
    #     print("Piece from 0 -",len(currentplayer.hand)-1," ?")
    #     piece = currentplayer.hand[int(input())]
    #     side = input("Side? [left/right] ")

    #     game.placePiece(side, piece)


def stringify_values( d ):
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

def unstringify_values( d ):
    newd = {}
    for key, value in d:
        # newkey = literal_eval(key)
        newvalue = value.encode('raw_unicode_escape')
        newd[key] = newvalue
    return newd

def stringify_keys( d ):
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

def unstringify_keys( d ):
    newd = {}
    for key, value in d:
        # newkey = literal_eval(key)
        newkey = key.encode('raw_unicode_escape')
        newvalue = value.encode('raw_unicode_escape')
        newd[newkey] = newvalue
    return newd

def main():
    autoRun()

if __name__ == "__main__":
    main()