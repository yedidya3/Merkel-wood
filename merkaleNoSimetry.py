from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import hashlib

def encrypt_string(hash_string):
    sha_signature = \
        hashlib.sha256(hash_string.encode()).hexdigest()
    return sha_signature

#secrate key need to save
def createPrivateKey():
    return rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
    )
# private_key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048,
#     backend=default_backend()
#     )
#save to pem in bytes

def PrivateKeyTobytes(private_key):
    return  private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
    )
# pem = private_key.private_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PrivateFormat.TraditionalOpenSSL,
#     encryption_algorithm=serialization.NoEncryption()
#     )
# with open("sk.pme","wb") as f:
#     f.write(pem)

def createPublicKey(private_key):
    return private_key.public_key()
def publicKeyToBytes(public_key):
    return public_key.public_bytes(
    encoding=serialization.Encoding.PEM ,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
# public_key = private_key.public_key()
# pem = public_key.public_bytes(
#     encoding=serialization.Encoding.PEM ,
#     format=serialization.PublicFormat.SubjectPublicKeyInfo
#     )

# with open("pk.pme","wb") as f:
#     f.write(pem)


#message =  b"Hello"
def sign(message ,private_key ):
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
#עוד פיענוחים הצפנה וכו שיעור 7 סרטון 2 דקה 10
def ver(public_key ,signature , message):
    return public_key.verify(
        signature ,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


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
        #you root
        return node
    else:
        node.father.data = encrypt_string(node.father.left.data + node.father.right.data)
        node.father.level = node.level + 1
        return update2(node.father)
        

def add2(valueS , node):
    if(node.father == None and node.right == None and node.left == None):
        father = NodeMarkel(None,node,None,None,1) 
        brotherRight = NodeMarkel(valueS,None,None,father,0)
        father.right = brotherRight
        node.father = father
        node.father.data = encrypt_string(node.father.left.data + node.father.right.data)
        return father
    elif(node.right == None and node.left == None):
        father = NodeMarkel(None,node,None,node.father,0) 
        brotherRight = NodeMarkel(valueS,None,None,father,0)
        father.right = brotherRight
        node.father.right = father
        node.father = father
        return update(brotherRight)
    elif(node.right.level == node.left.level):
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

    else:
        return add2(valueS , node.right)

        


def printTree(node):
    if(node==None):
        return
    else:
        
        #print(node.level)
        printTree(node.left)
        print(node.data)
        printTree(node.right)


    
class TreeMarkel:
    def __init__(self,root=None):
        self.root = root
        self.count = 0
        
        
        self.exponnet = 1
    
    def add(self ,value):
        self.count+=1
        
        if(self.count>self.exponnet):
            self.exponnet*=2
           

        #valueS =  encrypt_string(value)
        valueS = value
        if self.root == None:
            self.root = NodeMarkel(valueS,None,None,None,0)
        else:
            self.root = add2(valueS ,self.root)
    def printme(self):
        printTree(self.root)
    
    
    def ProofOfInclusionStart(self,numleaf):
        arrayRet = []
        numleaf+=1
        
        if(self.count<numleaf or self.count==0):
            return arrayRet
        arrayRet.append(self.root.data)
        if(self.count==1):
            return arrayRet
        else:
            numLeafSubTreeTheoretical = self.exponnet
            self.ProofOfInclusion(arrayRet,numleaf,numLeafSubTreeTheoretical,self.root)
            return arrayRet


            
    
    
    
    def ProofOfInclusion(self, arrayRet,numLeaf,numLeafSubTreeTheoretical,node):
        if(node.level == 0):
            return
        elif(numLeaf>numLeafSubTreeTheoretical/2):
            arrayRet.append(node.left.data)
            numLeafNew = numLeaf-numLeafSubTreeTheoretical/2
            numLeafSubTreeTheoreticalNew = numLeafSubTreeTheoretical/2
            self.ProofOfInclusion(arrayRet,numLeafNew,numLeafSubTreeTheoreticalNew,node.right)
        else:
            arrayRet.append(node.right.data)
            self.ProofOfInclusion(arrayRet,numLeaf,numLeafSubTreeTheoretical/2,node.left)
        return

   
    
    



def main():

    T = TreeMarkel(None)
    T.add("0")
    T.add("1")
    T.add("2")
    T.add("3")
    T.add("4")
    T.add("5")
    T.add("6")
    T.add("7")
    while(True):
        txt = input()
        x = txt.split(" ", 1)
        if(x[0] == '1'):
            T.add(x[1])
        if(x[0] == '2'):
            if(T.root != None):
                print(T.root.data)
        if(x[0] == '3'):
            try:
                print (" ".join(map(str,T.ProofOfInclusionStart(int(x[1])))))
            except ValueError:
                print("number of leaf not a number")
        if(x[0] == '4'):
            inputArray = txt.split(" ")
            leafVal = inputArray[1]
            del inputArray[0]
            del inputArray[0]

            if(inputArray[0] != T.root.data):
                print(False)
            del inputArray[0]
            
          
            node = T.root
            for i in inputArray:
                if(node == None):
                    print(False) 
                elif(i == node.left.data):
                    node = node.right
                elif(i == node.right.data):
                    node = node.left
                else:
                    print(False)
                    break
            if(leafVal == node.data and node.level == 0):
                print(True) 
            else:
                print(False)            
        if(x[0] == '5'):
            # createPrivateKey()
            # PrivateKeyTobytes(private_key)
            # createPublicKey(private_key)
            # publicKeyToBytes(public_key)
            private_key = createPrivateKey()
            privateKeyBytes = PrivateKeyTobytes(private_key)
            public_key = createPublicKey(private_key)
            publicKeyBytes = publicKeyToBytes(public_key)
            print(privateKeyBytes + publicKeyBytes)
            #print(private_key + " " + public_key)
            print(type(private_key))
            print(type(public_key))
            

        if(x[0] == '6'):
            private_key = serialization.load_pem_private_key(
            str.encode(x[1]),#convert to bytes
            password=None,
            )
            print(sign(T.root.data ,private_key))
        if(x[0] == '7'):
            array = x[1].split(" ")
            key = array[0]
            signature = array[1]
            textToConfirm = array[2]
            print(T.root.data is ver(public_key ,signature , textToConfirm))


            
            


           




   
    # T.add("1")
    
    # T.add("2")
    # T.add("3")
    # T.add("4")
    # T.add("5")

    T.printme()
    #print(T.root.level)
    #print("Hello World!")

main()