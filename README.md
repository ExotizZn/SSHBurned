# Writeup - SSHBurned
> It's a disaster, the private key allowing to connect to all the machines leaked on the DW, fortunately we don't risk anything because it is not complete !
## A propos du challenge
On a une capture d'écran d'une clé RSA privée, sauf qu'il y a des parties cachées/effacées. Voici à quoi ressemble la capture d'écran :

![SSHBurned](burned_key.png)

## Comment résoudre ce challenge ?
Notre objectif est de reconstruire la clé à partir des données de la capture d'écran, pour ensuite accéder au serveur et récupérer le flag.
Pour reconstuire la clé il nous faut retrouver ces paramètres : N, e, d, p, et q
En analysant petit à petit, nous allons réussir à récupérer tous ces paramètres.

## OCR (Optical Character Recognition)

Le premier problème est de transcrire ce qu'il y a sur l'image sous forme de texte, pour cela on peut utiliser un [OCR(wiki)](https://fr.wikipedia.org/wiki/Reconnaissance_optique_de_caract%C3%A8res) pour avoir une transcription presque parfaite. Avec le premier [OCR](https://www.imagetotext.info/) trouvé sur internet, le résultat n'était pas parfait, il fallait donc vérifier que tous les caractères correspondaient bien à l'image. Voici ce qu'on obtient :

```         
-----BEGIN RSA PRIVATE KEY-----
MIIJKgIBAAKCAgEAvThwh/aGh09uNFojF9w+7CSrDM9qQSoF5fEECzdLcge+UKAU
[                         Burned! (x20)                        ]
oaSgWcL0tP5jvGiezCAs3x4ME5KfKtEKeFFT+YmPUmMKkdESBGkCggEBAOfbktsH
8zhYhwlTFtJm52C6ornmyw8mekuhfYyUFDcmsTOOR94WoV0TcyS15YWRkI2jquCt
amvOSAc2qU0EQgx0ny1GoqAPbO5Y4z1RWgb2eEK7GhWEoXqzVe/Rh12bKu3jRY//
D3IEt6Mnxv/AGnLImIGWZ+1pcuzsWpIEw/T81X79eBgkQGl7m248nL97GCc/dYKv
leJFlk4QecDwAsmLRelHv/Q3QSt887651dhP7qt5r0HYiU0xCt2P/F66XS2RXvvH
SFtt0DjHcwNgJ4pteWrlpb+vqBGdKaJwWImtLFqkkz9/YmRGoehPfKcFDtkqCsAg
6iuYC51vmvkyW+UCggEBANDsUpREo6GOvVi+UsnTmD/AuVKZ8B4ERSjTxfklM6fm
[                         Burned! (x10)                        ]
DQnD39UCggEBAKO4Hbpc05G+BrltY/kPHKcRAuktAtKy6/NjiSeFtKYlCUDl9FA6
KSBXcXchIdL29Oo27ocoyDCY4lvVgIfkJKPJ8Nom6ub827Gsuhv3Vrh5PHw7Qcuk
NFjLLo9dt/rdXrQuD9Vjp+no2gv5Q4qbn1V4YnvZTuU57rQN59rF1KIT59E706ek
+aEdBRJ0BuzACuOqjbcjT/iSszw4c63zjR0bYtyXm+N7xFixavMPoxHQjYUDXaGT
M+djU+n58MR9XeyD8DIuX7EAJr8AKmE7KLMkNnKz9t6EZrO/oI4HHayPYGWsxP3y
6Zy+m+5/rFnuz6dSIy9P8iopKuLnXmo2rZ8CggEABW2GTbIaYHFyTKKnAJF1DXp6
NvGXoidGDt0dMRzRefWsnPNQLTnew5ZHySdeSIAK8CulZ14qPfs8ELUkzJcvmeOj
[                         Burned! (x5)                         ]
-----END RSA PRIVATE KEY-----
```

D'après la taille de l'image, cela semble correspondre à une clé privée RSA de 4096 bits qui, lorsque de nouvelles clés sont générées, comporte également 51 lignes.

## Trouver quelles sont les parties du RSA sont lisibles

La clé privée est encodée en PEM (Privacy-Enhanced Mail) et les paramètres sont toujours encodés dans le même ordre : $n$, $e$, $d$, $p$, $q$, $d \pmod{p-1}$, $d \pmod{q-1}$ et $q^-1 \pmod{p}$.

```         
PrivateKeyInfo ::= SEQUENCE {
   version Version,
   privateKeyAlgorithm AlgorithmIdentifier ,
   privateKey PrivateKey,
   attributes [0] Attributes OPTIONAL
}

RSAPrivateKey ::= SEQUENCE {
  version           Version,
  modulus           INTEGER,  -- n
  publicExponent    INTEGER,  -- e
  privateExponent   INTEGER,  -- d
  prime1            INTEGER,  -- p
  prime2            INTEGER,  -- q
  exponent1         INTEGER,  -- d mod (p-1)
  exponent2         INTEGER,  -- d mod (q-1)
  coefficient       INTEGER,  -- (inverse of q) mod p
  otherPrimeInfos   OtherPrimeInfos OPTIONAL
}
```

Pour retrouver ces informations, on décode en base64 puis on encode en hexadécimal, on peut utiliser [CyberChief](https://gchq.github.io/CyberChef/) en utilisant la "recette" suivante : 
- Remove whitespace
- From base64
- To hex (Delimiter: none;  Bytes per line: 48)

En arrengeant un peu, ça nous donne :
```
-----BEGIN RSA PRIVATE KEY-----
3082092a0201000282020100bd387087f686874f6e345a2317dc3eec24ab0ccf6a412a05e5f1040b374b7207be50a014
[                                         Burned! (x20)                                        ]
a1a4a059c2f4b4fe63bc689ecc202cdf1e0c13929f2ad10a785153f9898f52630a91d11204690282010100e7db92db07
f3385887095316d266e760baa2b9e6cb0f267a4ba17d8c94143726b1338e47de16a15d137324b5e58591908da3aae0ad
6a6bce480736a94d04420c749f2d46a2a00f6cee58e33d515a06f67842bb1a1584a17ab355efd1875d9b2aede3458fff
0f7204b7a327c6ffc01a72c898819667ed6972ecec5a9204c3f4fcd57efd78182440697b9b6e3c9cbf7b18273f7582af
95e245964e1079c0f002c98b45e947bff437412b7cf3beb9d5d84feeab79af41d8894d310add8ffc5eba5d2d915efbc7
485b6dd038c7730360278a6d796ae5a5bfafa8119d29a2705889ad2c5aa4933f7f626446a1e84f7ca7050ed92a0ac020
ea2b980b9d6f9af9325be50282010100d0ec529444a3a18ebd58be52c9d3983fc0b95299f01e044528d3c5f92533a7e6
[                                         Burned! (x10)                                        ]
0d09c3dfd50282010100a3b81dba5cd391be06b96d63f90f1ca71102e92d02d2b2ebf363892785b4a6250940e5f4503a
29205771772121d2f6f4ea36ee8728c83098e25bd58087e424a3c9f0da26eae6fcdbb1acba1bf756b8793c7c3b41cba4
3458cb2e8f5db7fadd5eb42e0fd563a7e9e8da0bf9438a9b9f5578627bd94ee539eeb40de7dac5d4a213e7d13bd3a7a4
f9a11d05127406ecc00ae3aa8db7234ff892b33c3873adf38d1d1b62dc979be37bc458b16af30fa311d08d85035da193
33e76353e9f9f0c47d5dec83f0322e5fb10026bf002a613b28b3243672b3f6de8466b3bfa08e071dac8f6065acc4fdf2
e99cbe9bee7fac59eecfa752232f4ff22a292ae2e75e6a36ad9f02820100056d864db21a6071724ca2a70091750d7a7a
36f197a227460edd1d311cd179f5ac9cf3502d39dec39647c9275e48800af02ba5675e2a3dfb3c10b524cc972f99e3a3
[                                         Burned! (x5)                                         ]
-----END RSA PRIVATE KEY-----
``` 
Les données qu'on cherche commencent toujours par : $${\color{orange}02820101}$$
- $${\color{orange}02}$$, pour le type de données, ici un Integer (entier).
- $${\color{orange}82}$$, pour nous indiquer que les deux prochains bytes nous indique la taille de l'entier.
- $${\color{orange}0101}$$, la taille de l'entier, **257 bytes**
Pour savoir où sont ces données par rapport à une vraie clé on peut générer nouvelle une clé de 4096 bit et la comparer avec celle ci.

### Récuperer les données lisibles
L'analyse ci-dessus permet de récuperer ces données :
```python
e  = 65537 # hypothèse
N_upper_bits = 0xbd387087f686874f6e345a2317dc3eec24ab0ccf6a412a05e5f1040b374b7207be50a014
q_upper_bits = 0xd0ec529444a3a18ebd58be52c9d3983fc0b95299f01e044528d3c5f92533a7e6
p  = 0xe7db92db07f3385887095316d266e760baa2b9e6cb0f267a4ba17d8c94143726b1338e47de16a15d137324b5e58591908da3aae0ad6a6bce480736a94d04420c749f2d46a2a00f6cee58e33d515a06f67842bb1a1584a17ab355efd1875d9b2aede3458fff0f7204b7a327c6ffc01a72c898819667ed6972ecec5a9204c3f4fcd57efd78182440697b9b6e3c9cbf7b18273f7582af95e245964e1079c0f002c98b45e947bff437412b7cf3beb9d5d84feeab79af41d8894d310add8ffc5eba5d2d915efbc7485b6dd038c7730360278a6d796ae5a5bfafa8119d29a2705889ad2c5aa4933f7f626446a1e84f7ca7050ed92a0ac020ea2b980b9d6f9af9325be5
dq = 0xa3b81dba5cd391be06b96d63f90f1ca71102e92d02d2b2ebf363892785b4a6250940e5f4503a29205771772121d2f6f4ea36ee8728c83098e25bd58087e424a3c9f0da26eae6fcdbb1acba1bf756b8793c7c3b41cba43458cb2e8f5db7fadd5eb42e0fd563a7e9e8da0bf9438a9b9f5578627bd94ee539eeb40de7dac5d4a213e7d13bd3a7a4f9a11d05127406ecc00ae3aa8db7234ff892b33c3873adf38d1d1b62dc979be37bc458b16af30fa311d08d85035da19333e76353e9f9f0c47d5dec83f0322e5fb10026bf002a613b28b3243672b3f6de8466b3bfa08e071dac8f6065acc4fdf2e99cbe9bee7fac59eecfa752232f4ff22a292ae2e75e6a36ad9f
```
Sachant que nous avons **dq** et **p** en entier nous pouvons reconstruire la clé entièrement !
### Retrouver q
On sait que :</br>
$$e\times d = 1 \pmod{\Phi} \Rightarrow e\times dq = 1 \pmod{q-1} \Rightarrow e\times dq = 1 + k_p(p - 1) \Rightarrow q = \frac{e\times dp - 1}{k_p} + 1$$ </br>
la seule inconnue étant $k_p$. En utilisant Python, on trouve un nombre premier (q) assez rapidement :
```python
e  = 65537
p  = 0xe7db92db07f3385887095316d266e760baa2b9e6cb0f267a4ba17d8c94143726b1338e47de16a15d137324b5e58591908da3aae0ad6a6bce480736a94d04420c749f2d46a2a00f6cee58e33d515a06f67842bb1a1584a17ab355efd1875d9b2aede3458fff0f7204b7a327c6ffc01a72c898819667ed6972ecec5a9204c3f4fcd57efd78182440697b9b6e3c9cbf7b18273f7582af95e245964e1079c0f002c98b45e947bff437412b7cf3beb9d5d84feeab79af41d8894d310add8ffc5eba5d2d915efbc7485b6dd038c7730360278a6d796ae5a5bfafa8119d29a2705889ad2c5aa4933f7f626446a1e84f7ca7050ed92a0ac020ea2b980b9d6f9af9325be5
dq = 0xa3b81dba5cd391be06b96d63f90f1ca71102e92d02d2b2ebf363892785b4a6250940e5f4503a29205771772121d2f6f4ea36ee8728c83098e25bd58087e424a3c9f0da26eae6fcdbb1acba1bf756b8793c7c3b41cba43458cb2e8f5db7fadd5eb42e0fd563a7e9e8da0bf9438a9b9f5578627bd94ee539eeb40de7dac5d4a213e7d13bd3a7a4f9a11d05127406ecc00ae3aa8db7234ff892b33c3873adf38d1d1b62dc979be37bc458b16af30fa311d08d85035da19333e76353e9f9f0c47d5dec83f0322e5fb10026bf002a613b28b3243672b3f6de8466b3bfa08e071dac8f6065acc4fdf2e99cbe9bee7fac59eecfa752232f4ff22a292ae2e75e6a36ad9f

for kp in range(3, e):
    p_mul = dq * e - 1
    if p_mul % kp == 0:
        q = (p_mul // kp) + 1
        if isPrime(q):
            print(f"Possible q: {q}")

#Possible q : 26374102437938552598977775622060483564941500314335674804443257510028571664385965778520148629220143464889925307730624984655886405401554218568254661066445076586481679113841644050194447873723787162461543012337002755982601434748818509576542225526132966483988443573125757495135295391117287147865772800792401391613297064940589286914213118584678411153945438814897268219757126807288880913755889888919479171560601451898932412702813644044467295289077659388606527864266014327364474064223329857483595456677811551699807767067205117577945081726724217691993809787335512248532922434983136917526564642119204116724508610553934484006583
```
## Calculer N, phi ($\Phi$) et d
Nous avons tout pour calculer les derniers paramètres pour reconstruire la clé.
```python
N = p*q
phi = (p-1)*(q-1)
d = pow(e, -1, phi)
```

## Solution
En regourpant toutes les étapes on obtient la solution finale :
```python
from Crypto.Util.number import isPrime #pip install pycryptodome
from Crypto.PublicKey import RSA

e  = 65537
p  = 0xe7db92db07f3385887095316d266e760baa2b9e6cb0f267a4ba17d8c94143726b1338e47de16a15d137324b5e58591908da3aae0ad6a6bce480736a94d04420c749f2d46a2a00f6cee58e33d515a06f67842bb1a1584a17ab355efd1875d9b2aede3458fff0f7204b7a327c6ffc01a72c898819667ed6972ecec5a9204c3f4fcd57efd78182440697b9b6e3c9cbf7b18273f7582af95e245964e1079c0f002c98b45e947bff437412b7cf3beb9d5d84feeab79af41d8894d310add8ffc5eba5d2d915efbc7485b6dd038c7730360278a6d796ae5a5bfafa8119d29a2705889ad2c5aa4933f7f626446a1e84f7ca7050ed92a0ac020ea2b980b9d6f9af9325be5
dq = 0xa3b81dba5cd391be06b96d63f90f1ca71102e92d02d2b2ebf363892785b4a6250940e5f4503a29205771772121d2f6f4ea36ee8728c83098e25bd58087e424a3c9f0da26eae6fcdbb1acba1bf756b8793c7c3b41cba43458cb2e8f5db7fadd5eb42e0fd563a7e9e8da0bf9438a9b9f5578627bd94ee539eeb40de7dac5d4a213e7d13bd3a7a4f9a11d05127406ecc00ae3aa8db7234ff892b33c3873adf38d1d1b62dc979be37bc458b16af30fa311d08d85035da19333e76353e9f9f0c47d5dec83f0322e5fb10026bf002a613b28b3243672b3f6de8466b3bfa08e071dac8f6065acc4fdf2e99cbe9bee7fac59eecfa752232f4ff22a292ae2e75e6a36ad9f
q  = 0

for kp in range(3, e):
    p_mul = dq * e - 1
    if p_mul % kp == 0:
        q_temp = (p_mul // kp) + 1
        if isPrime(q_temp):
            q = q_temp

p = 29269324251761301005942990170376705342450835986924919786106268994532598047846775604676889043270000042470143950138516750742242018979947768090855433386939450821834839405834523001267386296317226476227829478660528448825818833018079522307724034941710277643812038040198039542071462184790172469975249267040982041055873067547712007710944578910127270565399414587234586730911832855903691687608123171153324547290923847530043949227593467399420752266756157331934235783149668816164493940801344128683420380566763966024889191064000567693918354282971506052172329774061986952172440009055027019016599074909181023139760914546625248123877

N = p*q
phi = (p-1)*(q-1)
d = pow(e, -1, phi)

key = RSA.construct((N,e,d,p,q))
pem = key.export_key('PEM')
print(pem.decode())
```

```
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
```

