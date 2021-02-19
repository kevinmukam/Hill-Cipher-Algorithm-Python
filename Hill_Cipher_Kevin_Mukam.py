#Network Security
#Hill Encryption/Decryption Algorithms
#February 15, 2021



# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------


import numpy as np
from pprint import pprint

#1 Hill Encryption Algorithm
def hill_enc (key_matrix, phrase):

  #The text I will return
  text = ""

  #Making the phrase uppercase to correspond to ascii 65-90, and remove the spaces
  phrase = phrase.upper()
  phrase = phrase.replace(" ", "")

  #If the phrase is not a multiple of 3, add "X" at the end to make it a multiple
  while (len(phrase)%3) != 0:
    phrase = phrase + "X"

  #Creating the matrix of numbers corresponding to each letter in the phrase
  num = []
  for aletter in phrase:
    num.append(ord(aletter)-65) #The new matrix of numbers between 0 and 25
  num = np.array(num)           #Turning it into a matrix

  key_matrix = np.array(key_matrix)
  temp = []
  j = 0

  while j<len(num):
    temp = (num[j:j+3])         #The small matrices of 3 numbers for each 3 letters
    prod = (np.dot(temp, key_matrix))%26    #Multiplying the 1x3 matrix with the 3x3 matrix and adding modulo 26

    #Adding 65 to each number to return to the Ascii (65-90) range
    prod[0] = prod[0]+65
    prod[1] = prod[1]+65
    prod[2] = prod[2]+65

    #Each character is added to the text and the loop is updated
    text += chr(prod[0]) + chr(prod[1]) + chr(prod[2])
    j+=3

  return text



# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------



#Writing a separate function that returns the inverse of a 3x3 matrix in Modulo 26 space
def MatrixInvMod26(key):
  #Creating the table of determinants
  Mod26invTable = {}
  for m in range(26):
    for minv in range(26):
      if (m*minv)%26 == 1:      #Finding known determinants
        Mod26invTable[m] = minv

  #Encryption key matrix
  M = np.array(key)

  #Finding the normal inverse of the 3x3 encryption key matrix
  Minv = np.linalg.inv(M)

  #Finding the normal determinant of the 3x3 encryption key matrix
  Mdet = np.linalg.det(M)

  #Finding the modulo 26 of that determinant
  MdetMod26 = Mdet%26

  #If the determinant we found is in the table of determinants with inverses, we can proceed
  if MdetMod26 in Mod26invTable:
    MdetMod26inv = Mod26invTable[MdetMod26]
  else:
    MdetMod26inv = -1

  #Finding the adjunct of the matrix
  Madj = Mdet * Minv

  #Finding the adjunct in modulo 26 space
  MadjMod26 = Madj%26

  #The inverse of the matrix in modulo 26 space is finally given by
  MinvMod26 = (MdetMod26inv * MadjMod26)%26

  return MinvMod26



# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------



#2 Hill Decryption Algorithm
def hill_dec (key_matrix, ciph):
  text2 = ""

  #Making my ciphertext uppercase to correspond to ascii 65-90, and remove the spaces
  ciph = ciph.upper()
  ciph = ciph.replace(" ", "")

  #If the ciphertext's length is not a multiple of 3, add "X" at the end to make it a multiple
  while (len(ciph)%3) != 0:
    ciph = ciph + "X"

  #Creating the new matrix of numbers corresponding to each letter in the cipher text
  arr = []
  for lett in ciph:
    arr.append(ord(lett) - 65) #The new matrix of numbers between 0 and 25
  arr = np.array(arr)

  #Finding the inverse of the encryption matrix, such that K*K^(-1) = I
  key_matrix = np.array(key_matrix)
  key_matrix_inverse = MatrixInvMod26(key_matrix)

  #The interesting part
  j = 0
  while j<len(arr):
    temp = (arr[j:j+3])
    prod = (np.dot(temp, key_matrix_inverse))%26  #Multiplying the inverse mod26 matrix with the ciphertext matrix

    #For each number in the product, I add 65 to return to ASCII 65-90 alphabet range
    #Then, I round up that number from decimal to the nearest whole number
    prod[0] = prod[0] + 65
    entry0 = round(prod[0])

    prod[1] = prod[1] + 65
    entry1 = round(prod[1])

    prod[2] = prod[2] + 65
    entry2 = round(prod[2])

    #Each character is then added to the text
    text2 += chr(entry0) + chr(entry1) + chr(entry2)

    j+=3

  return text2



# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------



#Main code with testing
if __name__ == "__main__":

  M = np.array([[17,17,5],[21,18,21],[2,2,19]])
  word = "Test String"
  ciphertext = hill_enc(M,word)
  print("HILL: For the plaintext \"",word,"\", the encrypted text is ", ciphertext)
  recovery = hill_dec(M, ciphertext)
  print("HILL: For the ciphertext \"",ciphertext,"\", the encrypted text is ", recovery)
