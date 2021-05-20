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
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
    )
#save to pem in bytes
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
    )
with open("sk.pme","wb") as f:
    f.write(pem)

public_key = private_key.public_key()
pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM ,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

with open("pk.pme","wb") as f:
    f.write(pem)


#message =  b"Hello"
def sign(message):
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
#עוד פיענוחים הצפנה וכו שיעור 7 סרטון 2 דקה 10
def ver(signature , message):
    public_key.verify(
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

def update(node):
    if(node.father == None):
        #you root
        return node
    else:
        node.father.data = encrypt_string(node.father.left.data + node.father.right.data)
        node.father.level += 1
        return update(node.father)
        

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
            return update(brotherRight)

    else:
        return add2(valueS , node.right)

        




    # if(node.level == 0 and node.father == None):
    #     father = NodeMarkel(None,node,None,node.father,0) 
    #     brotherRight = NodeMarkel(valueS,None,None,father,0)
    #     node.father = father
    #     father.right = brotherRight
    #     return update(brotherRight)
    # elif(node.right.level == node.left.level ):
    #     father = NodeMarkel(None,node,None,node.father,0)
    #     brotherRight = NodeMarkel(valueS,None,None,father,0)
    #     node.father = father
    #     father.right = brotherRight
    #     return update(brotherRight)
    # else:
    #     return add2(valueS , node.right)



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
        
        self.countExponnet = 1
        self.exponnet = 0

    def add(self ,value):
        self.count+=1
        
        if(self.count==self.countExponnet):
            self.countExponnet*=2
            self.exponnet+=1

        valueS =  encrypt_string(value)
        #valueS = value
        if self.root == None:
            self.root = NodeMarkel(valueS,None,None,None,0)
        else:
            self.root = add2(valueS ,self.root)
    def printme(self):
        printTree(self.root)
    def ProofOfInclusion(numLeaf):
       


    

        


def main():

    T = TreeMarkel(None)
    while(True):
        txt = input()
        x = txt.split(" ", 1)
        if(x[0] == '1'):
            T.add(x[1])
        if(x[0] == '2'):
            if(T.root != None):
                print(T.root.data)
        if(x[0] == '3'):
            print(T.root.data)
        if(x[0] == '4'):
            break




   
    # T.add("1")
    
    # T.add("2")
    # T.add("3")
    # T.add("4")
    # T.add("5")

    T.printme()
    #print(T.root.level)
    #print("Hello World!")

main()