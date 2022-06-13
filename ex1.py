# Bachar Yedidya 1 
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import hashlib


#convertStringHexToStringInt
#this function convert string of hex to string of bits
def convertStringHexToStringInt(stringHex):
    scale = 16 ## equals to hexadecimal

    num_of_bits = 256
    
    return bin(int(stringHex, scale))[2:].zfill(num_of_bits)

#convert string to base 64
def stringToBase64(s):
    return base64.b64encode(s.encode('utf-8'))
#convert from base 64 to string
def base64ToString(b):
    message_bytes = base64.b64decode(b+ "==")
    message = message_bytes.decode('ascii')
    return message

 
#Performs a hash on a string
def encrypt_string(hash_string):
    sha_signature = \
        hashlib.sha256(hash_string.encode()).hexdigest()
    return sha_signature

#create private key in rsa algorithm
def createPrivateKey():
    return rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
    )
#convert private key to bytes
def PrivateKeyTobytes(private_key):
    return  private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
    )

#create public key from private key
def createPublicKey(private_key):
    return private_key.public_key()
#convert public key to bytes
def publicKeyToBytes(public_key):
    return public_key.public_bytes(
    encoding=serialization.Encoding.PEM ,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

#get message and private key and sign
#return the sign
def sign(message ,private_key):
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
# Checks whether the signature and the public key form the string we sent
#If so then returns true otherwise returns false
def ver(public_key ,signature , message):
    # RSA verify message
    try:
        public_key.verify(
        signature ,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
        )
    #if throw return false
    except Exception as exception:
        return False
    #else return true
    return True 

#An object of Merkel wood
#containing
#data
# son left
# son rught
# father level
class NodeMarkel:
    def __init__(self , data=None , left=None , right=None,father=None,level=0):
        self.data=data
        self.left=left
        self.right=right
        self.father = father
        self.level=level

#If the leaf is added at the end of the tree the levels should be raised
def update(node):
    if(node.father == None):
        #you root
        return node
    else:
        node.father.data = encrypt_string(node.father.left.data + node.father.right.data)
        node.father.level += 1
        return update(node.father)

#If the leaf is added in the middle of the tree the levels should be updated accordingly (reduce the parent levels)
def update2(node):
    if(node.father == None):
        return node
    else:
        node.father.data = encrypt_string(node.father.left.data + node.father.right.data)
        node.father.level = node.level + 1
        return update2(node.father)
        
#Given the vertex of the Merkel tree the function checks how to insert the next son
def add2(valueS , node):
    # If there is only one vertex
    # starting position
    if(node.father == None and node.right == None and node.left == None):
        father = NodeMarkel(None,node,None,None,1) 
        brotherRight = NodeMarkel(valueS,None,None,father,0)
        father.right = brotherRight
        node.father = father
        node.father.data = encrypt_string(node.father.left.data + node.father.right.data)
        return father
    #If we got to the leaf
    elif(node.right == None and node.left == None):
        father = NodeMarkel(None,node,None,node.father,0) 
        brotherRight = NodeMarkel(valueS,None,None,father,0)
        father.right = brotherRight
        node.father.right = father
        node.father = father
        return update(brotherRight)
    #If we have reached vertices at the same level then some logic has to be used
    elif(node.right.level == node.left.level):
        #if all the wood is equal
        if(node.father == None):
            father = NodeMarkel(None,node,None,node.father,1) 
            brotherRight = NodeMarkel(valueS,None,None,father,0)
            father.right = brotherRight
            node.father = father
            node.father.data = encrypt_string(node.father.left.data + node.father.right.data)
            return father
        else:
            father = NodeMarkel(None,node,None,node.father,1) 
            brotherRight = NodeMarkel(valueS,None,None,father,0)
            father.right = brotherRight
            node.father.right = father
            node.father = father
            return update2(brotherRight)
    #Default
    else:
        return add2(valueS , node.right)
#function to tests
def printTree(node):
    if(node==None):
        return
    else:
        printTree(node.left)
        print(node.data)
        printTree(node.right)
#input 4 check Proof Of Inclusion
#Goes from leaf to vertex and checks each pair (temp,arrayLeaf) whether they are forming their father
def checkProofOfInclusionInput4(leaf , root, arrayLeafs):
    temp = leaf
    
    for i in arrayLeafs:
        if(i[0] == '0'):
            t = i[1:]
            temp = encrypt_string(t+temp)
        elif(i[0] == '1'):
            t = i[1:]
            temp = encrypt_string(temp + t)
    #End
    if(root != temp):
        return False
    else:
        return True

#object of Tree markel
class TreeMarkel:
    def __init__(self,root=None):
        self.root = root
        self.count = 0      
        self.exponnet = 1  
    #add leaf to Tree
    def add(self ,value):
        self.count+=1
        if(self.count>self.exponnet):
            self.exponnet*=2
        valueS =  encrypt_string(value)
        #if Tree empthy
        if self.root == None:
            self.root = NodeMarkel(valueS,None,None,None,0)
        else:
            self.root = add2(valueS ,self.root)
    #function to tests
    def printme(self):
        printTree(self.root) 
    #Test Proof Of Inclusion at start
    def ProofOfInclusionStart(self,numleaf):
        arrayRet = []
        numleaf+=1
        #If there is no such leaf number in the tree
        if(self.count<numleaf or self.count==0):
            return arrayRet
        #If there is only one leaf
        if(self.count==1):
            arrayRet.append(self.root.data)
            return arrayRet
        else:
            numLeafSubTreeTheoretical = self.exponnet
            self.ProofOfInclusion(arrayRet,numleaf,numLeafSubTreeTheoretical,self.root)
            arrayRet.append(self.root.data)
            arrayRet.reverse()
            return arrayRet
    #Test recursion of Proof Of Inclusion
    # Here is the whole logic of testing proof      
    def ProofOfInclusion(self, arrayRet,numLeaf,numLeafSubTreeTheoretical,node):
        #If we've reached the leaf then we'll be back
        if(node.level == 0):
            return
        elif(numLeaf>numLeafSubTreeTheoretical/2):
            #if digit 0 the proof from son left and need to go right
            temp = '0' + node.left.data
            arrayRet.append(temp)
            numLeafNew = numLeaf-numLeafSubTreeTheoretical/2
            numLeafSubTreeTheoreticalNew = numLeafSubTreeTheoretical/2
            self.ProofOfInclusion(arrayRet,numLeafNew,numLeafSubTreeTheoreticalNew,node.right)
        else:
            #if digit 0 the proof from son right and need to go left
            temp = '1' + node.right.data
            arrayRet.append(temp)
            self.ProofOfInclusion(arrayRet,numLeaf,numLeafSubTreeTheoretical/2,node.left)
        return
#object of sparse Merkle Tree
class sparseMerkleTree:
    def __init__(self):
        #create array of hashes we need and save in tree
        self.hashBlankVertices = []
        #start of array the leaf with value '0'
        self.hashBlankVertices.append('0')
        #preform the all hashes
        for i in range(1,257):
            self.hashBlankVertices.append(encrypt_string(self.hashBlankVertices[i-1]+self.hashBlankVertices[i-1]))
        self.root = NodeMarkel(self.hashBlankVertices[256],None,None,None,256)
    #Marking a particular leaf about 1
    #In the notation we get in hex coding the trajectory of the leaf
    def MarkLeaf(self ,digitStr):
        #convert to bytes
        digitStr = convertStringHexToStringInt(digitStr)
        #to list
        digitArray = list(digitStr)
        #check size
        if(len(digitArray) != 256):
            raise ValueError('oops!')
        #check digit
        if((digitArray.count('0')+digitArray.count('1')) != len(digitArray)):
           raise ValueError('oops!')
        self.MarkLeafRecursion(self.root ,digitArray)
    # update hash after add
    def MarkLeafHashUpdate(self , node):
        #if we in root we finish
        if(node.father == None):
            return
        else:
            dataLeft = None
            dataRight  = None
            #if left none take value from array hash in same level
            if(node.father.left == None):
                dataLeft =  self.hashBlankVertices[node.level]
            #else take the real data
            else:
                dataLeft = node.father.left.data
            #if right none take value from array hash in same level
            if(node.father.right == None):
                dataRight =  self.hashBlankVertices[node.level]
            #else take the real data
            else:
                dataRight = node.father.right.data
            node.father.data = encrypt_string(dataLeft + dataRight)
            self.MarkLeafHashUpdate(node.father)
    #mark leaf
    def MarkLeafRecursion(self , node ,digitArray):
        if(node.level <= 0):
            node.data = '1'
            self.MarkLeafHashUpdate(node)
        else:
            #Choose where to go by the array of digits
            if(digitArray[0] == '0'):
                del digitArray[0]
                if(node.left == None):
                    node.left = NodeMarkel(None,None,None,node,node.level-1)
                self.MarkLeafRecursion(node.left ,digitArray)
            elif(digitArray[0] == '1'):
                del digitArray[0]
                if(node.right == None):
                    node.right = NodeMarkel(None,None,None,node,node.level-1)
                self.MarkLeafRecursion(node.right ,digitArray)
            else:
                raise ValueError('oops!')
    #get data of root
    def dataOfRoot(self):
        return self.root.data
    #create Proof Of Inclusion in sparseMerkleTree to digitStr
    def createProofOfInclusion(self ,digitStr ,array):
        #convert hex to bin
        digitStr = convertStringHexToStringInt(digitStr)
        #convert to list
        digitArray = list(digitStr)
        if(len(digitArray) != 256):
            raise ValueError('oops!')
        if((digitArray.count('0')+digitArray.count('1')) != len(digitArray)):
            raise ValueError('oops!')
        if(self.root.data  == self.hashBlankVertices[256]):
            array.append(self.dataOfRoot())
            array.append(self.dataOfRoot())
            return
        self.createProofOfInclusionRecurse(self.root ,digitArray,array)
        #add the root
        array.append(self.dataOfRoot())
        #reverse
        array.reverse()
    #create Proof Of Inclusion in Recurse
    def createProofOfInclusionRecurse(self ,node ,digitArray,arrayOfInclusion ):
        #createProofOfInclusionRecurse
        if(node.level <= 0):
            return arrayOfInclusion
        else:
            #If the check is 0 then the proof should be taken from the opposite side (right)
            if(digitArray[0] == '0'):
                del digitArray[0]
                #take proof from oppsite side
                if(node.right == None):
                    arrayOfInclusion.append(self.hashBlankVertices[node.level-1])
                #take real data
                else:
                    arrayOfInclusion.append(node.right.data)
                #dont nead continue
                if(node.left == None):
                    if(node.level == 1):
                        return
                    arrayOfInclusion.append(self.hashBlankVertices[node.level-1])
                    return
                else:
                    self.createProofOfInclusionRecurse(node.left ,digitArray,arrayOfInclusion)
                    return
            #If the check is 1 then the proof should be taken from the opposite side (left)
            if(digitArray[0] == '1'):
                del digitArray[0]
                if(node.left == None):
                    arrayOfInclusion.append(self.hashBlankVertices[node.level-1])
                else:
                    arrayOfInclusion.append(node.left.data)
                if(node.right == None):
                    if(node.level == 1):
                        return
                    arrayOfInclusion.append(self.hashBlankVertices[node.level-1])
                    return
                else:
                    self.createProofOfInclusionRecurse(node.right ,digitArray,arrayOfInclusion)
                    return
            else:
                raise ValueError('oops!')
    #check proof of inclusion of SMT
    def checkProofSMT(self , digest , classification , proof):
        arrayProof = proof.split(" ")
        #convert string digit to bytes
        digest = convertStringHexToStringInt(digest)
        digitArray = list(digest)
        #checkes
        if(len(digitArray) != 256):
            raise ValueError('oops!')
        if((digitArray.count('0')+digitArray.count('1')) != len(digitArray)):
            raise ValueError('oops!')
        if(arrayProof[0] != self.root.data):
            return False
        del arrayProof[0]
        arrayProof.reverse()
        #send to function
        return self.checkProofSMTRecursion(self.root ,digitArray,classification, arrayProof)
    #check proof in recurse
    def checkProofSMTRecursion(self ,node , arrayDigest ,classification ,arrayProof):
        if(node.level == 0):
            if(classification == node.data):
                return True
            else:
                return False
        if not arrayDigest:
            return False
        left = ""
        right = ""
        finish  = False
        if(arrayDigest[0] == '0'):
            if(node.left == None):
                finish = True
                left = self.hashBlankVertices[node.level-1]   
            else:
                left = node.left.data
            right = arrayProof[0]
            if(encrypt_string(left+right) != node.data):
                return False
            if(finish == True):
                if(classification ==  '0'):
                    return True
                else:
                    return False
            del arrayDigest[0]
            del arrayProof[0]
            self.checkProofSMTRecursion(self ,node.left , arrayDigest ,classification ,arrayProof)


        if(arrayDigest[0] == '1'):
            if(node.right == None):
                finish = True
                right = self.hashBlankVertices[node.level-1]   
            else:
                right = node.right.data
            left = arrayProof[0]
            if(encrypt_string(left+right) != node.data):
                return False
            if(finish == True):
                if(classification == '0'):
                    return True
                else:
                    return False
            del arrayDigest[0]
            del arrayProof[0]
            self.checkProofSMTRecursion(self ,node.right , arrayDigest ,classification ,arrayProof)


   

    
def main():
    #print(encrypt_string('b'))
    #create Trees
    T = TreeMarkel(None)
    SMT = sparseMerkleTree()
    
    #T.add("0")
    # T.add("1")
    # T.add("2")
    # T.add("3")
    # a = encrypt_string('0')
    # b = encrypt_string('1')
    # c = encrypt_string(a+b)
    # d = encrypt_string('2')
    # e = encrypt_string(c+d)
    #d = encrypt_string('3')

    # print("0 " +a)
    # print("1 " + b)
    
    # print("c " + c)
    # print("d " + d)
    # print("e " + e)
    # T.add("4")
    # T.add("5")
    # T.add("6")
    # T.add("7")

    #SMT.MarkLeaf("1111")
    #SMT.MarkLeaf("1001")
    #T.add("7")
    # loop input
    while(True):
        try:
            txt = input()
          
            x = txt.split(" ",1)
            #input 1 add to TreeMerkel
            if(x[0] == '1'):
                T.add(x[1])  
            #input 2 print the data of root Tree merkle
            elif(x[0] == '2'):
            
                if(T.root != None):
                    print(T.root.data)
                else:
                    raise ValueError('oops!')         
            #input 3 printcreate proof of inclusion
            elif(x[0] == '3'):
                
                if(int(x[1])>=T.count):
                    print ()
                else:
                    print (" ".join(map(str,T.ProofOfInclusionStart(int(x[1])))))
            #input 4 print True of proof right
            elif(x[0] == '4'):
                inputArray = txt.split(" " , 3)
                leaf = encrypt_string(inputArray[1])
                root = inputArray[2]
                arrayLeafs = inputArray[3].split(" ")
                print(checkProofOfInclusionInput4(leaf , root, arrayLeafs))
            #input 5 public key and private 
            elif(x[0] == '5'):
                
                private_key = createPrivateKey()
                privateKeyBytes = PrivateKeyTobytes(private_key)
                public_key = createPublicKey(private_key)
                publicKeyBytes = publicKeyToBytes(public_key)
                s = (privateKeyBytes +'\n'.encode() +publicKeyBytes).decode()
                print(s)
            #input 6 print sign on root
            elif(x[0] == '6'):
                
                partB= x[1] + "\n"
               
                partC = ""
                while True:
                    partC = input()
                    
                    if(partC == "-----END RSA PRIVATE KEY-----"):
                        break
                    partB = partB+partC
                    
                stam = input()
                key = partB+ "\n" + partC+ "\n"

                #key = x[1]+"\n" + partB +"\n" +partC +"\n"
                key = key.encode().decode('unicode-escape').encode()
                
                private_key = serialization.load_pem_private_key(
                key,
                password=None,
                )
            
                s = sign(T.root.data.encode() ,private_key)
                
                s = base64.b64encode(s)
                s = s.decode()
                print(s)
            #input 7 check sign with key and sign
            elif(x[0] == '7'):
                
               
                partB= x[1] + "\n"
               
                partC = ""
                while True:
                    partC = input()
                    
                    if(partC == "-----END PUBLIC KEY-----"):
                        break
                    partB = partB+partC
                    
                stam = input()
                key = partB+ "\n" + partC+ "\n"

                txtnew = input().split(" ")
                s = txtnew[0]
                textToConfirm =  txtnew[1]
                message_bytes = s.encode('ascii')
                s = base64.b64decode(message_bytes)
                #s = base64_bytes.decode('ascii')
                
            
                textToConfirm = textToConfirm.encode()
               
                key = key.encode().decode('unicode-escape').encode()
                
                public_key = serialization.load_pem_public_key(
                    key,
                    #.encode().decode('unicode-escape').encode(),
                    )
                print(ver(public_key ,s , textToConfirm))
            

            elif(x[0] == '8'):      
                SMT.MarkLeaf(x[1])
            elif(x[0] == '9'):
                print(SMT.dataOfRoot())
            elif(x[0] == '10'):
                array = []
                SMT.createProofOfInclusion(x[1],array)
                print(' '.join(array))
            elif(x[0] == '11'):
                
                array = x[1].split(" ",2)
                digest = array[0]
                classification = array[1]
                proof = array[2]
                print(SMT.checkProofSMT(digest,classification,proof))
                
          
        #except Exception as exception:
        except ValueError:
                    print() 
main()

