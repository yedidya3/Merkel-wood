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

# def rsa_verify(public_key, message, signature):
#     """ RSA verify message  """
#     try:
#         public_key.verify(
#             base64.b64decode(signature),
#             message,
#             padding.PSS(
#                 mgf=padding.MGF1(hashes.SHA256()),
#                 salt_length=padding.PSS.MAX_LENGTH
#                 ),
#             hashes.SHA256()
#         )
#     except exceptions.InvalidSignature:
#         return False
#     except Exception as e:
#         raise e
#     return True 
#עוד פיענוחים הצפנה וכו שיעור 7 סרטון 2 דקה 10
def ver(public_key ,signature , message):
    """ RSA verify message  """
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
    except Exception as exception:
        return False
    # except Exception as e:
    #     raise e
    return True 


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
           

        valueS =  encrypt_string(value)
        #valueS = value
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
    #T.add("7")
    while(True):
        txt = input()
        x = txt.split(" ",1)
        if(x[0] == '1'):
            try:
                T.add(x[1])
            except Exception as exception:
                print("need to int number to add")
        if(x[0] == '2'):
            if(T.root != None):
                print(T.root.data)
        if(x[0] == '3'):
            try:
                if(int(x[1])>=T.count):
                    print ("The number you gave is greater than the number of leaves in the tree")
                else:
                    print (" ".join(map(str,T.ProofOfInclusionStart(int(x[1])))))
            except Exception as exception:
                print("You did not enter a number as input")
        if(x[0] == '4'):
            try:    
                inputArray = txt.split(" ")
                leafVal = inputArray[1]
                del inputArray[0]
                del inputArray[0]

                if(inputArray[0] != T.root.data):
                    #print(False)
                    raise Exception("False")
                del inputArray[0]
                
            
                node = T.root
                for i in inputArray:
                    if(node == None):
                        #print(False) 
                        raise Exception("False")
                    elif(i == node.left.data):
                        node = node.right
                    elif(i == node.right.data):
                        node = node.left
                    else:
                        #print(False)
                        raise Exception("False")
                       
                        break
                if(leafVal == node.data and node.level == 0):
                    print(True) 
                else:
                    #print(False)  
                    raise Exception("False")
            except Exception as exception:
                print(False)          
        if(x[0] == '5'):
            #צריך לבדוק באיזה פורמט
            private_key = createPrivateKey()
            privateKeyBytes = PrivateKeyTobytes(private_key)
            public_key = createPublicKey(private_key)
            publicKeyBytes = publicKeyToBytes(public_key)
            print(privateKeyBytes + publicKeyBytes)
            
            
        if(x[0] == '6'):
             
            

#-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA79zZis341pOMrEapNSyLHBrfuNQ0s1xhEqTKT2iKpF/8/Hz+\n/3r73jxrrP6VQ6vHPAQKXldiSTMX/X2BS2cCRa+5AdMTUclPtVXo40fNynvlWgNF\nV6da6MmFF66nmzowg7z1Q1+1Oi7yxAEaUZvD7U/1hPcqL1dex7EvtGmtCTbW0p5u\nacLBD4jqur7Hdz/b8rzbnyY97109+qPL/VjII9Dp7Hidf1ijXUljz1iIDcfFuV5x\nje/+CUt++yM8KuYmAc/VaD6TUFv0jHMJI0YSkb/6PCNotl9Z6fm92+5I8gm0Pe0J\nbH8guro35W6YIOEO9Wur2HfhkbqOuMdDz4i3UQIDAQABAoIBAEf6+6GG7BzgjH+K\neO7HHjvh6K9bpzEIEO16XGf2FFz9nTrb+94JNxpbAWkZwQtcul5NTBtBl/IljhZ5\nGlrZX7ov4JImmI6bnfrp/AhwnNYd1hbsElwakdJ33yPbOtr/XF28T9HXH9iFDD87\noX1KBELsEt7DGXq5emzsxEccy1uO77AdXCyndvMTm8Zs32ZoP97kh3Sq0kBjyNPG\nUTogz8sxA6NeWw4Lft90sEgSjwFL0Bz9i2dmEYaVdGphcvWw4KdsDX2HlP7+oEOA\nbWHkk/bB2T9RDx4JAic2eg57sP5crgm5mfxrGxQC3I22auVsTcrKWdrtuVheWKQG\nDiQWr20CgYEA+QKGoOYajkViibaXchI5gHKYGTrtjDH5Jg42bLqO8KHcMGOl1P+E\nKKZOgh3W16dnTZS3NH9JnZxWj1pVL6A1+XoPNXvXhLvOa0dEOLF2ZLmT6WKapFvi\nurbW+TYzg+y37RtDf/KJOMfen/OHGLfwWlDMQTdup2uArfSsRl8C3IcCgYEA9piW\nykyJL0f2XLhjSnhOor1AflMP0qSyojFmp8wdSwfz4YD8xQgbpJPDL7tWGFPN6Jw6\nudYZXg+j3izDM5272HA1gMekczSB4gRCaz+UiG4TQYEOOMzFpK1KI+eBogtMYjzK\noRn8rmnHhwQGIZML+Q7JCR354HnS0w36tNSSW2cCgYEA2qABG9trjWYV8dtCdIDT\nw5bZO62lSuXFXkg0OJpDTbqO3F1hB/WfTyFU5KDWNFliNZdQkuL++0Z8KTiiekIr\noXItUEP/ISbTQRU9LJmC3USiPNK5+3xBQLWvYPbZnAaGJcM+LGQBXrz9FWp3Ppig\nimtOKiRFHvEf9ZtQdiiNFpkCgYABrKWReBWSYZ21oXbjIY//IOPYN74qwv2HhmhZ\nCVTFlqc8R8DvoY92fZ5cq5v5DFCgnLb1XhPMBLUrJAirSA3neVOTrUdblOaw3zCI\nQ+VBS+YLktHC5vkMljSjq8XAkO0S2bDSiTejA4rcStWz0qjJJyWMT0zMDme1ESo7\nohngTwKBgG6CrYMPAIMy0PwfEgnlnfH5L+0wLWKNyEGbfjnn1DNe4R6ufrR7LE1C\nOK+8qp585+MfdIopptESRauF2IeRe7gXoZpkKtjUwCTpmVRRar5Te+8abZFEbiRo\ns+/O6ao1pAIZJg5JoEinz3v+UhmwXwOtzq+uTscq5GWaLPvRJ2c5\n-----END RSA PRIVATE KEY-----\n           
#MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA79zZis341pOMrEapNSyL\nHBrfuNQ0s1xhEqTKT2iKpF/8/Hz+/3r73jxrrP6VQ6vHPAQKXldiSTMX/X2BS2cC\nRa+5AdMTUclPtVXo40fNynvlWgNFV6da6MmFF66nmzowg7z1Q1+1Oi7yxAEaUZvD\n7U/1hPcqL1dex7EvtGmtCTbW0p5uacLBD4jqur7Hdz/b8rzbnyY97109+qPL/VjI\nI9Dp7Hidf1ijXUljz1iIDcfFuV5xje/+CUt++yM8KuYmAc/VaD6TUFv0jHMJI0YS\nkb/6PCNotl9Z6fm92+5I8gm0Pe0JbH8guro35W6YIOEO9Wur2HfhkbqOuMdDz4i3\nUQIDAQAB         
            try:
                key2 = x[1]
                key = "-----BEGIN RSA PRIVATE KEY-----\n"+ key2 + "\n-----END RSA PRIVATE KEY-----\n"
                key= key.encode().decode('unicode-escape').encode()

                private_key = serialization.load_pem_private_key(
                key,
                password=None,
                )
                print(sign(T.root.data.encode() ,private_key))
            except Exception as exception:
                print("There is a problem please try again")    
                       
        if(x[0] == '7'):
            try:
                array = x[1].split(" ")
                key2 = array[0]

    #-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEAmsSg6oQdd/Fb3poGAfRP9Ian1kSlBEeFZ2e3MopruQrB+jbW\nDMqDJn6k9x1NSaBNA6cFKNBt/z3WTt6Eg2dd/A9ETxspxq8LVoIUdQ9tqT6mrFKH\n3DavajDB0wliGcJ3NmMvnRkOVw3qZmh4CtkttBjTgxRDLIltU8ZxYomSVtGkOF+4\nwpltfoU1t66d7piMYBHAYDBLL8WJrKZDiE2KmmEH4v3X77604tpl2W2/3x2FCKLb\nxpqPUS+UGdk6zBLb/uXpHwA/DY1zzlxrFlltDPEoDt8oSwImmOVTRY6wYt7IRvy8\nAElsOF0D0/VluDAxQ9MU7XshE/uYujrX/4rcnwIDAQABAoIBACf0cTJ57v2jAruh\n+cERaH7RMI0hZZSIPklmviW/FHZN76v/8hyVP2x1r3LYTraeOqOhv7Q8stj9BtGP\nopgl3F6RNmpRseRIFl478LoTxJS3xuGf4NEaEQkSE0e/GWNbD9mrm4QsDsasogHU\nIIF0ddcTva8OURUzWVUSWv08VNoymDNmGYsSp5PXxOaaE8DbWD7K//dG7cuQIl1e\n+lPsjq+H81Bryfn1hDOZBh3cwfbipdMD9H9F+JQzGcNNALs5BETESURx7LH7dKM2\nbE5S9OOPzI8YQy3dNwA2sZ5EwU0xWXct5hLhhc5ceWEvJBx4+aK8manIx99eRXGn\ni5g+SPkCgYEAx0moQBppCKnNPh1G6bb3jPUMlUr7jmhG6BB9XMxGF6MVFpiEpT7s\n30k3ztAtiirhd1BKNrdzkBlFKFaeyujCzytJ/aL7GDDM1VwSrL6l/GbKcBJMm2FB\nGm2yMgCw1A0JCLZ8LdNL1EuVHPimGtFX5l3/8LHkffC7+jSycFHF8sUCgYEAxs+p\n2rfFWRESE2C90uN/3+X0hyZ401EgZaN2e2mRPLSHh8rjUfw5hi0c3gRZrYA8SPKW\nqJyLLlVhZVstLpB5iBn5fStDdXQmbO2PCQhZteFZHjKT0TovIINq57JJrMtz7p0V\n6Kl2sOCoIXqhY3Muzzyz816E3RY71t7KT76v+BMCgYA3WXPLagpmB5Mjf0oku1aB\n5cV66Xp4kOmwpnPLBEkrY3YF8pJUuudbFKDVZehgCYzZcIlMLSOBkCMvEu/Dd2Yz\n19gTA+MtUtBxKcNeCw1azsnG2q5AMYC9cF4fmSWDn6M0skpHB/p1mhBuHXk01ZPO\nPalKFn5ZpDTxRxWQMIYD6QKBgEuoQ09EmAlpAaP2MMbMZKFj9UZpUZm5ScbkCfa1\nGdwsJ1d50kAk6A8zo8SpiycHoelwx/yqdhzPyRy1MeCCgn1UxSjpCebsqKLTVJdv\nYhRhCXUAclgw+DY7TLeXlYn4csnfZbMAqnZtSA5ViI08DBg5VZHL6mvoRiVi60Kl\nonmZAoGANzir4Bk/bDjRJTpSwo8t5ZDs8+rSXGis4pXn22z2hIOmP1umh5ZvMPlA\nx8TGgFzRfLcFoIe2lOorpuRcMtUt1rITo3/+pmwsGuZZM4sUCd173kyzEfUk52MZ\nmim5XF69JtRP6kQJOLnLCS1RDNvciBdot5pldjwq8EP/XvBIrqw=\n-----END RSA PRIVATE KEY-----\n
    #-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmsSg6oQdd/Fb3poGAfRP\n9Ian1kSlBEeFZ2e3MopruQrB+jbWDMqDJn6k9x1NSaBNA6cFKNBt/z3WTt6Eg2dd\n/A9ETxspxq8LVoIUdQ9tqT6mrFKH3DavajDB0wliGcJ3NmMvnRkOVw3qZmh4Ctkt\ntBjTgxRDLIltU8ZxYomSVtGkOF+4wpltfoU1t66d7piMYBHAYDBLL8WJrKZDiE2K\nmmEH4v3X77604tpl2W2/3x2FCKLbxpqPUS+UGdk6zBLb/uXpHwA/DY1zzlxrFllt\nDPEoDt8oSwImmOVTRY6wYt7IRvy8AElsOF0D0/VluDAxQ9MU7XshE/uYujrX/4rc\nnwIDAQAB\n-----END PUBLIC KEY-----\n
    #\x05]\'z8E\xb2\xb8\x1d\t\xb3K\x03\x7f(\x91Yz\xaaO\xf8=\'~\x9bn\x00u\x91\xb5\xaf\xa9h\xcc\xd0B\xf5\xa7\xed\xcc\x0fi\x96:\x05"\xc5%\x02\xdd\xd8\x1a\xd7\x88\xc2\x88\x02\x0f}!\xf5\xda\xa3^\x14\x16\xf9\xab\x9d\x1eR\x1a\x0b\t\xad\xea|3E\xd8\x9b\x0c\x02\xfe\xc8\x8b\xd9S\xed\x14"\xe7\xf7\xa7|\x94\xe8\xda\x81\x08\xf8@\xa2/s7\xf2o3\x92\x99\xe3\xc5\xb0K\x13\x931\xa8\xaa\xff\xf4\xc5\x7f\xff3\xb4\xb4\xddYXC&\xf3`\xe5\xfc\x9a\xc2\xd1\xe2\'\xd7\xe5\xfa\t\xee\x148\xb1Pa":\xc1t\xca\x88\xce\xbeV\x80\xde7%\x1eq\xe90\x99u\xe7F_v@\x8bUi\xbbg\xca\x82\xa2V\xa1n><\x0e\x96\xc6\x01m^\xa7a\xc7\t\x129a7\x95A\xe2\xb1S\x1b@\xb1\xe4\xd2\xe1LH\xdf=j\xe7\x83+\x1a4\xdb\x9ex=i\xff\x1e\xa5\xe9\xd5\xff\x18\xb2\x16g\xa1J\x14c\x96t\xe9\xdb\x15h\x19\x05\xb4\xca\xe8\xea\x9e
    #789a758b0ce412b1ded74d9e8482de93c9e1c1e0bd2d8a2a8c83cbc7ec7e0dca
    #MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmsSg6oQdd/Fb3poGAfRP\n9Ian1kSlBEeFZ2e3MopruQrB+jbWDMqDJn6k9x1NSaBNA6cFKNBt/z3WTt6Eg2dd\n/A9ETxspxq8LVoIUdQ9tqT6mrFKH3DavajDB0wliGcJ3NmMvnRkOVw3qZmh4Ctkt\ntBjTgxRDLIltU8ZxYomSVtGkOF+4wpltfoU1t66d7piMYBHAYDBLL8WJrKZDiE2K\nmmEH4v3X77604tpl2W2/3x2FCKLbxpqPUS+UGdk6zBLb/uXpHwA/DY1zzlxrFllt\nDPEoDt8oSwImmOVTRY6wYt7IRvy8AElsOF0D0/VluDAxQ9MU7XshE/uYujrX/4rc\nnwIDAQAB \x05]\'z8E\xb2\xb8\x1d\t\xb3K\x03\x7f(\x91Yz\xaaO\xf8=\'~\x9bn\x00u\x91\xb5\xaf\xa9h\xcc\xd0B\xf5\xa7\xed\xcc\x0fi\x96:\x05"\xc5%\x02\xdd\xd8\x1a\xd7\x88\xc2\x88\x02\x0f}!\xf5\xda\xa3^\x14\x16\xf9\xab\x9d\x1eR\x1a\x0b\t\xad\xea|3E\xd8\x9b\x0c\x02\xfe\xc8\x8b\xd9S\xed\x14"\xe7\xf7\xa7|\x94\xe8\xda\x81\x08\xf8@\xa2/s7\xf2o3\x92\x99\xe3\xc5\xb0K\x13\x931\xa8\xaa\xff\xf4\xc5\x7f\xff3\xb4\xb4\xddYXC&\xf3`\xe5\xfc\x9a\xc2\xd1\xe2\'\xd7\xe5\xfa\t\xee\x148\xb1Pa":\xc1t\xca\x88\xce\xbeV\x80\xde7%\x1eq\xe90\x99u\xe7F_v@\x8bUi\xbbg\xca\x82\xa2V\xa1n><\x0e\x96\xc6\x01m^\xa7a\xc7\t\x129a7\x95A\xe2\xb1S\x1b@\xb1\xe4\xd2\xe1LH\xdf=j\xe7\x83+\x1a4\xdb\x9ex=i\xff\x1e\xa5\xe9\xd5\xff\x18\xb2\x16g\xa1J\x14c\x96t\xe9\xdb\x15h\x19\x05\xb4\xca\xe8\xea\x9e 789a758b0ce412b1ded74d9e8482de93c9e1c1e0bd2d8a2a8c83cbc7ec7e0dca
                key = "-----BEGIN PUBLIC KEY-----\n"+ key2 + "\n-----END PUBLIC KEY-----\n"
                #print(key.encode().decode('unicode-escape').encode())
                signature = array[1].encode('latin1').decode('unicode-escape').encode('latin1')
                textToConfirm = array[2].encode().decode('unicode-escape').encode()
            
                public_key = serialization.load_pem_public_key(
                    key.encode().decode('unicode-escape').encode(),
                    
                    )
                print(ver(public_key ,signature , textToConfirm))
            except Exception as exception:
                print("There is a problem please try again") 
            
        #tests
        if(x[0] == '8'):
            stringy = '''-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA79zZis341pOMrEapNSyLHBrfuNQ0s1xhEqTKT2iKpF/8/Hz+\n/3r73jxrrP6VQ6vHPAQKXldiSTMX/X2BS2cCRa+5AdMTUclPtVXo40fNynvlWgNF\nV6da6MmFF66nmzowg7z1Q1+1Oi7yxAEaUZvD7U/1hPcqL1dex7EvtGmtCTbW0p5u\nacLBD4jqur7Hdz/b8rzbnyY97109+qPL/VjII9Dp7Hidf1ijXUljz1iIDcfFuV5x\nje/+CUt++yM8KuYmAc/VaD6TUFv0jHMJI0YSkb/6PCNotl9Z6fm92+5I8gm0Pe0J\nbH8guro35W6YIOEO9Wur2HfhkbqOuMdDz4i3UQIDAQABAoIBAEf6+6GG7BzgjH+K\neO7HHjvh6K9bpzEIEO16XGf2FFz9nTrb+94JNxpbAWkZwQtcul5NTBtBl/IljhZ5\nGlrZX7ov4JImmI6bnfrp/AhwnNYd1hbsElwakdJ33yPbOtr/XF28T9HXH9iFDD87\noX1KBELsEt7DGXq5emzsxEccy1uO77AdXCyndvMTm8Zs32ZoP97kh3Sq0kBjyNPG\nUTogz8sxA6NeWw4Lft90sEgSjwFL0Bz9i2dmEYaVdGphcvWw4KdsDX2HlP7+oEOA\nbWHkk/bB2T9RDx4JAic2eg57sP5crgm5mfxrGxQC3I22auVsTcrKWdrtuVheWKQG\nDiQWr20CgYEA+QKGoOYajkViibaXchI5gHKYGTrtjDH5Jg42bLqO8KHcMGOl1P+E\nKKZOgh3W16dnTZS3NH9JnZxWj1pVL6A1+XoPNXvXhLvOa0dEOLF2ZLmT6WKapFvi\nurbW+TYzg+y37RtDf/KJOMfen/OHGLfwWlDMQTdup2uArfSsRl8C3IcCgYEA9piW\nykyJL0f2XLhjSnhOor1AflMP0qSyojFmp8wdSwfz4YD8xQgbpJPDL7tWGFPN6Jw6\nudYZXg+j3izDM5272HA1gMekczSB4gRCaz+UiG4TQYEOOMzFpK1KI+eBogtMYjzK\noRn8rmnHhwQGIZML+Q7JCR354HnS0w36tNSSW2cCgYEA2qABG9trjWYV8dtCdIDT\nw5bZO62lSuXFXkg0OJpDTbqO3F1hB/WfTyFU5KDWNFliNZdQkuL++0Z8KTiiekIr\noXItUEP/ISbTQRU9LJmC3USiPNK5+3xBQLWvYPbZnAaGJcM+LGQBXrz9FWp3Ppig\nimtOKiRFHvEf9ZtQdiiNFpkCgYABrKWReBWSYZ21oXbjIY//IOPYN74qwv2HhmhZ\nCVTFlqc8R8DvoY92fZ5cq5v5DFCgnLb1XhPMBLUrJAirSA3neVOTrUdblOaw3zCI\nQ+VBS+YLktHC5vkMljSjq8XAkO0S2bDSiTejA4rcStWz0qjJJyWMT0zMDme1ESo7\nohngTwKBgG6CrYMPAIMy0PwfEgnlnfH5L+0wLWKNyEGbfjnn1DNe4R6ufrR7LE1C\nOK+8qp585+MfdIopptESRauF2IeRe7gXoZpkKtjUwCTpmVRRar5Te+8abZFEbiRo\ns+/O6ao1pAIZJg5JoEinz3v+UhmwXwOtzq+uTscq5GWaLPvRJ2c5\n-----END RSA PRIVATE KEY-----\n'''           
            private_key = serialization.load_pem_private_key(
            stringy.encode(),
            password=None,
            )
            public_key = createPublicKey(private_key)
            sign1 = sign(T.root.data.encode() ,private_key)
            public_key.verify(sign1,T.root.data.encode(),padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
                )
            print(ver(public_key ,sign1 , T.root.data.encode()))
            for x in range(5):
                print(2)
                #print(sign(T.root.data.encode() ,private_key))
        if(x[0] == '9'):
            data = '''789a758b0ce412b1ded74d9e8482de93c9e1c1e0bd2d8a2a8c83cbc7ec7e0dca'''
            privStr = '''-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEAmsSg6oQdd/Fb3poGAfRP9Ian1kSlBEeFZ2e3MopruQrB+jbW\nDMqDJn6k9x1NSaBNA6cFKNBt/z3WTt6Eg2dd/A9ETxspxq8LVoIUdQ9tqT6mrFKH\n3DavajDB0wliGcJ3NmMvnRkOVw3qZmh4CtkttBjTgxRDLIltU8ZxYomSVtGkOF+4\nwpltfoU1t66d7piMYBHAYDBLL8WJrKZDiE2KmmEH4v3X77604tpl2W2/3x2FCKLb\nxpqPUS+UGdk6zBLb/uXpHwA/DY1zzlxrFlltDPEoDt8oSwImmOVTRY6wYt7IRvy8\nAElsOF0D0/VluDAxQ9MU7XshE/uYujrX/4rcnwIDAQABAoIBACf0cTJ57v2jAruh\n+cERaH7RMI0hZZSIPklmviW/FHZN76v/8hyVP2x1r3LYTraeOqOhv7Q8stj9BtGP\nopgl3F6RNmpRseRIFl478LoTxJS3xuGf4NEaEQkSE0e/GWNbD9mrm4QsDsasogHU\nIIF0ddcTva8OURUzWVUSWv08VNoymDNmGYsSp5PXxOaaE8DbWD7K//dG7cuQIl1e\n+lPsjq+H81Bryfn1hDOZBh3cwfbipdMD9H9F+JQzGcNNALs5BETESURx7LH7dKM2\nbE5S9OOPzI8YQy3dNwA2sZ5EwU0xWXct5hLhhc5ceWEvJBx4+aK8manIx99eRXGn\ni5g+SPkCgYEAx0moQBppCKnNPh1G6bb3jPUMlUr7jmhG6BB9XMxGF6MVFpiEpT7s\n30k3ztAtiirhd1BKNrdzkBlFKFaeyujCzytJ/aL7GDDM1VwSrL6l/GbKcBJMm2FB\nGm2yMgCw1A0JCLZ8LdNL1EuVHPimGtFX5l3/8LHkffC7+jSycFHF8sUCgYEAxs+p\n2rfFWRESE2C90uN/3+X0hyZ401EgZaN2e2mRPLSHh8rjUfw5hi0c3gRZrYA8SPKW\nqJyLLlVhZVstLpB5iBn5fStDdXQmbO2PCQhZteFZHjKT0TovIINq57JJrMtz7p0V\n6Kl2sOCoIXqhY3Muzzyz816E3RY71t7KT76v+BMCgYA3WXPLagpmB5Mjf0oku1aB\n5cV66Xp4kOmwpnPLBEkrY3YF8pJUuudbFKDVZehgCYzZcIlMLSOBkCMvEu/Dd2Yz\n19gTA+MtUtBxKcNeCw1azsnG2q5AMYC9cF4fmSWDn6M0skpHB/p1mhBuHXk01ZPO\nPalKFn5ZpDTxRxWQMIYD6QKBgEuoQ09EmAlpAaP2MMbMZKFj9UZpUZm5ScbkCfa1\nGdwsJ1d50kAk6A8zo8SpiycHoelwx/yqdhzPyRy1MeCCgn1UxSjpCebsqKLTVJdv\nYhRhCXUAclgw+DY7TLeXlYn4csnfZbMAqnZtSA5ViI08DBg5VZHL6mvoRiVi60Kl\nonmZAoGANzir4Bk/bDjRJTpSwo8t5ZDs8+rSXGis4pXn22z2hIOmP1umh5ZvMPlA\nx8TGgFzRfLcFoIe2lOorpuRcMtUt1rITo3/+pmwsGuZZM4sUCd173kyzEfUk52MZ\nmim5XF69JtRP6kQJOLnLCS1RDNvciBdot5pldjwq8EP/XvBIrqw=\n-----END RSA PRIVATE KEY-----\n'''
            private_key = serialization.load_pem_private_key(
            privStr.encode(),
            password=None,
            )
            sign1 = sign(T.root.data.encode() ,private_key)
            sign2 = b'#\xd0\x17\xda\x17\x19\xca\x97\x8a\xfd\xe1\x05\xf8C\xeemf\xaeR\x1b\xa8\xafNI\xb5\x08P\xd2Q!+(\x88n\x8c35/\x12\xd5\xcd\xbc\x08\x18\x16gw0U\r \xe0m\xea<\n\xbf\xd8\x81\xdc&\x818p\x83M\xfd\x97\xb7\xffm\x7f-\xa8\xdf"\xf7s\xcdD[%\x96\x1e,J\x892\x94tjV\x80l\x00\xa5GP\xb5o\x1b\xc3\xdd\x05\xd3\x95\x04\x9fd\x85\x8cI\xedg\xeaH5\x85\x04\x91\xd0\x12(\xb2\x9d\xf4\xecEMW6\xa9\xe3\x00w\xc6oZ\x02\xd0\xc7\x02\xda\xa0\xf0\xe5\x80\xf3}\xd8\xf1fI\xbax\x02\x06v\xfd(\xfcd\xda\x88\xbcTm\xa2\xb6T\xbdz\xba}\xb8l\xd8eE\x01\xbc\x8b\xc9,\t(\x17d|\xfb\x89\xeeV"\x95\x19f\x973\x81\xcd\x8d\r\xcbF\x7f5\x08\x93\x1d\xd4\xbeM\xdd\x05V\xe5\xa2\x08?]\x0c/\x9f\xba\x15L\x0f\xda\xadzx\x8b\xedJ\x1a^\x04\x08OWN\xecPo<`\xd2\x1c"\xbdZ!\xd2\x07\x0c'
            sign4 = '#\xd0\x17\xda\x17\x19\xca\x97\x8a\xfd\xe1\x05\xf8C\xeemf\xaeR\x1b\xa8\xafNI\xb5\x08P\xd2Q!+(\x88n\x8c35/\x12\xd5\xcd\xbc\x08\x18\x16gw0U\r \xe0m\xea<\n\xbf\xd8\x81\xdc&\x818p\x83M\xfd\x97\xb7\xffm\x7f-\xa8\xdf"\xf7s\xcdD[%\x96\x1e,J\x892\x94tjV\x80l\x00\xa5GP\xb5o\x1b\xc3\xdd\x05\xd3\x95\x04\x9fd\x85\x8cI\xedg\xeaH5\x85\x04\x91\xd0\x12(\xb2\x9d\xf4\xecEMW6\xa9\xe3\x00w\xc6oZ\x02\xd0\xc7\x02\xda\xa0\xf0\xe5\x80\xf3}\xd8\xf1fI\xbax\x02\x06v\xfd(\xfcd\xda\x88\xbcTm\xa2\xb6T\xbdz\xba}\xb8l\xd8eE\x01\xbc\x8b\xc9,\t(\x17d|\xfb\x89\xeeV"\x95\x19f\x973\x81\xcd\x8d\r\xcbF\x7f5\x08\x93\x1d\xd4\xbeM\xdd\x05V\xe5\xa2\x08?]\x0c/\x9f\xba\x15L\x0f\xda\xadzx\x8b\xedJ\x1a^\x04\x08OWN\xecPo<`\xd2\x1c"\xbdZ!\xd2\x07\x0c'
            pubStr = '''-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmsSg6oQdd/Fb3poGAfRP\n9Ian1kSlBEeFZ2e3MopruQrB+jbWDMqDJn6k9x1NSaBNA6cFKNBt/z3WTt6Eg2dd\n/A9ETxspxq8LVoIUdQ9tqT6mrFKH3DavajDB0wliGcJ3NmMvnRkOVw3qZmh4Ctkt\ntBjTgxRDLIltU8ZxYomSVtGkOF+4wpltfoU1t66d7piMYBHAYDBLL8WJrKZDiE2K\nmmEH4v3X77604tpl2W2/3x2FCKLbxpqPUS+UGdk6zBLb/uXpHwA/DY1zzlxrFllt\nDPEoDt8oSwImmOVTRY6wYt7IRvy8AElsOF0D0/VluDAxQ9MU7XshE/uYujrX/4rc\nnwIDAQAB\n-----END PUBLIC KEY-----\n'''
            signStr = '''\x05]\'z8E\xb2\xb8\x1d\t\xb3K\x03\x7f(\x91Yz\xaaO\xf8=\'~\x9bn\x00u\x91\xb5\xaf\xa9h\xcc\xd0B\xf5\xa7\xed\xcc\x0fi\x96:\x05"\xc5%\x02\xdd\xd8\x1a\xd7\x88\xc2\x88\x02\x0f}!\xf5\xda\xa3^\x14\x16\xf9\xab\x9d\x1eR\x1a\x0b\t\xad\xea|3E\xd8\x9b\x0c\x02\xfe\xc8\x8b\xd9S\xed\x14"\xe7\xf7\xa7|\x94\xe8\xda\x81\x08\xf8@\xa2/s7\xf2o3\x92\x99\xe3\xc5\xb0K\x13\x931\xa8\xaa\xff\xf4\xc5\x7f\xff3\xb4\xb4\xddYXC&\xf3`\xe5\xfc\x9a\xc2\xd1\xe2\'\xd7\xe5\xfa\t\xee\x148\xb1Pa":\xc1t\xca\x88\xce\xbeV\x80\xde7%\x1eq\xe90\x99u\xe7F_v@\x8bUi\xbbg\xca\x82\xa2V\xa1n><\x0e\x96\xc6\x01m^\xa7a\xc7\t\x129a7\x95A\xe2\xb1S\x1b@\xb1\xe4\xd2\xe1LH\xdf=j\xe7\x83+\x1a4\xdb\x9ex=i\xff\x1e\xa5\xe9\xd5\xff\x18\xb2\x16g\xa1J\x14c\x96t\xe9\xdb\x15h\x19\x05\xb4\xca\xe8\xea\x9e'''
            sign3 = bytes(sign4, 'utf-8')
            #sign6 = bytes(sign4,'')
            sign5 = x[1].encode('latin1').decode('unicode-escape').encode('latin1')
            # print(sign2)
            # print()
            # print(sign3)
            print()
            print(sign5)


            public_key = serialization.load_pem_public_key(
                pubStr.encode(),#.decode('unicode-escape').encode(),
                #backend=backends.default_backend()
                )
            print(ver(public_key ,sign5 , data.encode()))
            
            #print(ver(public_key ,sign3 , data.encode()))
        if(x[0] == '10'):
            T.printme()
    
main()