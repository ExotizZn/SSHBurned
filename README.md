# Writeup - SSHBurned

## OCR (Optical Character Recognition)
---

Le premier problème est de retranscrire ce qu'il y a sur l'image sous forme de texte, pour cela on peut utiliser un OCR pour avoir une transcription presque parfaite. Avec le premier OCR trouvé sur internet, le résultat n'était pas parfait il fallait donc vérifier que tous les caractères correspondait bien à l'image. Voici ce qu'on obtient :

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

## Trouver quelles sont les parties du RSA sont lisible
---

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

Pour retrouver ces informations, on décode en base64 puis on encode en hexadécimal, pour cela on peut utiliser [CyberChief](%22https://gchq.github.io/CyberChef/%22) en utilisant la "recette" suivante : 
- Remove whitespace
- From base64
- To hex (Delimiter: none;  Bytes per line: 48)
&nbsp;
&nbsp;

En arrengeant un peu ça nous donne : <font size=2>
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
</font>

Les données qu'on cherche commence toujours par : **02820101**
- **02**, pour le type de données, ici un Integer (entier).
- **82**, pour nous indiquer que les deux prochains bytes nous indique la taille de l'entier.
- **0101**, la taille de l'entier, 257 bytes
Pour savoir où sont ces données par rapport à une vraie clé on peut générer nouvelle une clé de 4096 bit et la comparer avec celle ci.

### Récuperer les données lisibles<font size=2>
```python
e  = 65537 # hypothèse
N_upper_bits = 0xbd387087f686874f6e345a2317dc3eec24ab0ccf6a412a05e5f1040b374b7207be50a014
q_upper_bits = 0xd0ec529444a3a18ebd58be52c9d3983fc0b95299f01e044528d3c5f92533a7e6
p  = 0xe7db92db07f3385887095316d266e760baa2b9e6cb0f267a4ba17d8c94143726b1338e47de16a15d137324b5e58591908da3aae0ad6a6bce480736a94d04420c749f2d46a2a00f6cee58e33d515a06f67842bb1a1584a17ab355efd1875d9b2aede3458fff0f7204b7a327c6ffc01a72c898819667ed6972ecec5a9204c3f4fcd57efd78182440697b9b6e3c9cbf7b18273f7582af95e245964e1079c0f002c98b45e947bff437412b7cf3beb9d5d84feeab79af41d8894d310add8ffc5eba5d2d915efbc7485b6dd038c7730360278a6d796ae5a5bfafa8119d29a2705889ad2c5aa4933f7f626446a1e84f7ca7050ed92a0ac020ea2b980b9d6f9af9325be5
dq = 0xa3b81dba5cd391be06b96d63f90f1ca71102e92d02d2b2ebf363892785b4a6250940e5f4503a29205771772121d2f6f4ea36ee8728c83098e25bd58087e424a3c9f0da26eae6fcdbb1acba1bf756b8793c7c3b41cba43458cb2e8f5db7fadd5eb42e0fd563a7e9e8da0bf9438a9b9f5578627bd94ee539eeb40de7dac5d4a213e7d13bd3a7a4f9a11d05127406ecc00ae3aa8db7234ff892b33c3873adf38d1d1b62dc979be37bc458b16af30fa311d08d85035da19333e76353e9f9f0c47d5dec83f0322e5fb10026bf002a613b28b3243672b3f6de8466b3bfa08e071dac8f6065acc4fdf2e99cbe9bee7fac59eecfa752232f4ff22a292ae2e75e6a36ad9f
```
