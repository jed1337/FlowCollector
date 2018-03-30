import Attributes.feature as feature
import os.path


class ArffWriter():
   NEW_LINE  = "\n"

   RELATION  = "@relation "
   ATTRIBUTE = "@attribute"
   DATA      = "@data"

   SCRIPT_DIR = os.path.dirname(__file__)
   # OUTPUT_DIR = "../Bi flow output/"

   def __init__(self, output_file_path, output_file_name, c_attribute, features):
      """
      :param output_file_name: output_file_path+output_file_name
      :param c_attribute: Class attribute (normal,slowHeaders,slowRead,tcpFlood,udpFlood,httpFlood)
      :param features: The features to extract implemented in Scripts/Attributes/feature.py
      """
      self.output_path = os.path.join(ArffWriter.SCRIPT_DIR, output_file_path, output_file_name)
      self.class_attribute = "," + c_attribute #The "," is there since the c_attribute is always gonna be appended to the data
      self.features = features


   def _write_attribute_name(self):
      """:return: "@attribute (feature name) (data type)" """
      attributes = [" ".join([ArffWriter.ATTRIBUTE, feature.data_type_holder().name, feature.data_type_holder().type])
                    for feature in self.features]
      # attributes.append("@attribute isAttack {normal,slowHeaders,slowRead,tcpFlood,udpFlood,httpFlood}")
      attributes.append("@attribute isAttack {tcpFlood,normal,httpFlood,slowRead,slowHeaders,udpFlood}")
      return attributes


   def write_headers(self):
      """Writes the headers to self.output_file if it doesn't exist"""
      if not os.path.isfile(self.output_path):
         # Create the directories on the relative path in addition to the file
         os.makedirs(os.path.dirname(self.output_path), exist_ok=True)

         with open(self.output_path, 'w') as file:
            # @relation (classAttribtue)
            file.write(ArffWriter.RELATION)
            file.write(self.class_attribute)

            file.write(ArffWriter.NEW_LINE)
            file.write("\n".join(self._write_attribute_name()))
            file.write(ArffWriter.NEW_LINE)
            file.write(ArffWriter.DATA)
      else:
         print("%s already exists, not creating the file again" %self.output_path)


   def write_pcap_path(self, pcap_path):
      """
      This function just writes the pcap_path as a comment into the arff file.
      It's done for debugging purposes as well as to keep track of where the written area is
      """
      with open(self.output_path, 'a+') as file:
         file.write(ArffWriter.NEW_LINE)
         file.write("% "+pcap_path)
         file.write(ArffWriter.NEW_LINE)


   def write_data(self, flows):
      with open(self.output_path, 'a+') as file:
         for key, packets in flows.items():
            print("Current key: %s" %key)
            feature_string=[feature.action(packets) for feature in self.features]
            file.write(",".join(map(str, feature_string)))
            file.write(self.class_attribute)
            file.write(ArffWriter.NEW_LINE)