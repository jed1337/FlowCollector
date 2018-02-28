import numpy as np

def max_agg(arr):
   return max(arr)


def min_agg(arr):
   return min(arr)


def mean_agg(arr):
   return np.mean(arr)


def std_agg(arr):
   return np.std(arr)


def var_agg(arr):
   return np.var(arr)


def no_agg(arr):
   """
   No aggregate function
   :return: The array unedited
   """
   return arr