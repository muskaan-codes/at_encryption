"""
-*- coding: utf-8 -*-
This class is an abstract class for the Encryption Classes, to maintain a basic blueprint of any current/ future encryption classes
Created: April 2023
Owners: Project 4a: Muskaan Manocha, Prem Desai, Yeshaswini Murthy
"""

from abc import (
  ABC,
  abstractmethod,
)

class Encryption(ABC):
    """
    Abstract class for encryption utilities.
    """
    
    @abstractmethod
    def encrypt(self):
        """
        Encrypts the given clear text string according to the algorithm implementation in child class and returns the encrypted text.
        """
        pass
    
    @abstractmethod
    def decrypt(self):
        """
        Decrypts the given encrypted string according to the  algorithm implementation in child class and returns the clear text.
        """
        pass
    
    