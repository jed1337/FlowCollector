class ArffWriter():
   def __init__(self, path, features):
      self.path = path
      self.features = features
      pass


   def write_headers(self):
      with open(self.path, 'w') as file:
         for feature in self.features:
            print(feature)
            file.write(feature)


   def write_data(self, packets):
      # with open(self.path, 'w') as file:
      feature_string=[feature(packets) for feature in self.features]
      return ",".join(map(str, feature_string))