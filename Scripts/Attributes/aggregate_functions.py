import numpy as np

def max_agg(arr):
   return max(arr)


def min_agg(arr):
   return min(arr)


def std_agg(arr):
   return np.std(arr)


def mean_agg(arr):
   return np.mean(arr)


def no_agg(arr):
   """
   No aggregate function
   :return: The array unedited
   """
   return arr