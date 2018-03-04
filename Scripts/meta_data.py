import re

class MetaData:
   """
   A class that given a path to a pcap file, returns its attack type and where
   files pertaining to that attack type should be outputted
   """

   """
   Since the path to a pcap file is in the format (...)/(single letter)/(...), 
   this pattern tries to isolate /(single letter)/.
   
   (?i) makes it case insensitive
   """
   ATTACK_TYPE_PATTERN = re.compile("(?i)/[A-Z]/")

   NOISE_PATTERN = re.compile("(?i)/noise/")

   ATTACK_DICTIONARY = {"/N/": "normal",
                        "/B/": "slowBody", "/H/": "slowHeaders", "/X/": "slowRead",
                        "/T/": "tcpFlood", "/U/": "udpFlood", "/F/": "httpFlood"}

   def __init__(self, pcap_path):
      # Since the path has slashes, this pattern tries to normalise the slashes (both forward and backward slashes)
      # into "\". It's written as "\\" since we need to escape it
      formatted_pcap_path = re.sub(r"\\+?", "/", pcap_path)

      # .span() gives a tuple containing the start and end string wherein the match occured
      range = None
      for match in MetaData.ATTACK_TYPE_PATTERN.finditer(formatted_pcap_path):
         range = match.span()

      if range:
         self._known_attack(range, formatted_pcap_path)
      else:
         self._unknown_attack()

      # if self.is_noise exists (i.e.: not None)
      if self.is_noise:
         self._adjust_for_noise()


   def _adjust_for_noise(self):
      """
      Is executed if this file is noise.
      This appends "Noise" to the file name as well as turns the class_attribute to "Normal".
      """
      self.output_file_name = "Noise "+self.output_file_name
      self.class_attribute  = "normal"


   def _known_attack(self, range, formatted_pcap_path):
      """Assigns values to the variables if a valid attack is found"""

      # Attack letter = /(single letter)/
      attack_letter = formatted_pcap_path[range[0]:range[1]]

      # Looks up attack_letter in the dictinoary. It returns "?" if it isn't found
      self.class_attribute = MetaData.ATTACK_DICTIONARY.get(attack_letter, "?")

      self.output_file_name = "%s.arff" % self.class_attribute

      # If the noise pattern is found, something will be assigned here. None will be assigned otherwise
      # We can use None to check for noise.
      # if not self.is_noise: (assume that is_noise is None)
      #   (not noise since "not None" == True)
      self.is_noise = MetaData.NOISE_PATTERN.search(formatted_pcap_path)


   def _unknown_attack(self):
      """
      Assigns values to the variables if a valid attack isn't found.

      This can be due to reasons like: live testing, invalid file names, etc.

      self.is_noise is False since if it's live testing, or other reasons, the file isn't noise
      """
      self.class_attribute = "?"
      self.output_file_name = "bi flow to classify.arff"
      self.is_noise = False