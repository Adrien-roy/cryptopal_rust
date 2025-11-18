# set 1 


this is the really start this was mostly a way for me to learn the basics of rust 

the exercises are the following :


- Convert hex to base64
- Fixed XOR
- Single-byte XOR cipher
- Detect single-character XOR
- Implement repeating-key XOR
- Break repeating-key XOR
- AES in ECB mode
- Detect AES in ECB mode


For this set I needed to do conversion between base64 , hexadecimal,  or raw bite:
one of the first decision was to treat every string of character as vectors of 8 bits , to skip all issue with the miriads of ways to encode characters.
This solution also makes it easy to implement new encoding method later on if needed .

I personnaly come from C so I would generally use array , but vector are a much more logical way of handling strings so no complain here .

The xor operand is easy to use  I would normally do a for loop but here the map operator seemed appropriate I therefore used it .


now the the actuall cryptography :

# Break repeating-key XOR

trois fonctions sont necessaire 

## hamming distance 

The Hamming distance calculation measures how many bits differ between two text segments by counting the bits that are different. In cryptography, this distance is useful for estimating the key size in a Vigenère cipher because segments of the same length containing the same key tend to have lower Hamming distances. By comparing these normalized distances for different segment lengths, you can guess the likely length of the key. Since the alphabet used consists of 26 letters among 256 possible characters, the Hamming distance is a good indicator for determining the segment size during a cryptanalysis.

interestingly even if we had only 26 possible characters this would still work on a much bigger sample size because all letters are not the same frequency .

this function let us easily guess key size


## Vigenere 


now that the key length is known the message is broken into several groups based on the length of the key.
in our case the key has a length of 29 we therefore have 29 different group with a key made of a single character .

this can now be easily broken by itterating each character and scoring each solution by the number of common letters logically the correct text is the one that has the most of common letter .

what is interesting is that almost every criptography technique until set 5 will use the same scoring technique .


# Detect and Break ECB mode 

