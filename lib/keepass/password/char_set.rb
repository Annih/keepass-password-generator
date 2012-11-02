# encoding: utf-8
require 'set'

module KeePass
  
  module Password

    class InvalidCharSetIDError < RuntimeError; end
  
    # Character sets for the KeePass password generator.
    #
    # @see http://keepass.info/help/base/pwgenerator.html#pattern
    class CharSet < Set

      UPPERCASE        = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      LOWERCASE        = "abcdefghijklmnopqrstuvwxyz"
      DIGITS           = "0123456789"
      UPPER_CONSONANTS = "BCDFGHJKLMNPQRSTVWXYZ"
      LOWER_CONSONANTS = "bcdfghjklmnpqrstvwxyz"
      UPPER_VOWELS     = "AEIOU"
      LOWER_VOWELS     = "aeiou"
      PUNCTUATION      = ",.;:"
      BRACKETS         = "[]{}()<>"
      PRINTABLE_ASCII_SPECIAL = "!\"#\$%&'()*+,-./:;<=>?[\\]^_{|}~"
      UPPER_HEX        = "0123456789ABCDEF"
      LOWER_HEX        = "0123456789abcdef"
      HIGH_ANSI        = %w[007E 20AC 201A 0192 201E 2026 2020 2021 02C6 2030
                            0160 2039 0152 017D 2018 2019 201C 201D 2022 2013
                            2014 02DC 2122 0161 203A 0153 017E 0178 00A1 00A2
                            00A3 00A4 00A5 00A6 00A7 00A8 00A9 00AA 00AB 00AC
                            00AE 00AF 00B0 00B1 00B2 00B3 00B4 00B5 00B6 00B7
                            00B8 00B9 00BA 00BB 00BC 00BD 00BE 00BF 00C0 00C1
                            00C2 00C3 00C4 00C5 00C6 00C7 00C8 00C9 00CA 00CB
                            00CC 00CD 00CE 00CF 00D0 00D1 00D2 00D3 00D4 00D5
                            00D6 00D7 00D8 00D9 00DA 00DB 00DC 00DD 00DE 00DF
                            00E0 00E1 00E2 00E3 00E4 00E5 00E6 00E7 00E8 00E9
                            00EA 00EB 00EC 00ED 00EE 00EF 00F0 00F1 00F2 00F3
                            00F4 00F5 00F6 00F7 00F8 00F9 00FA 00FB 00FC 00FD
                            00FE].inject("") { |str, chr| str << chr.to_i(16) }
  
      DEFAULT_MAPPING = {
        'a' => [LOWERCASE, DIGITS],
        'A' => [LOWERCASE, UPPERCASE, DIGITS],
        'U' => [UPPERCASE, DIGITS],
        'c' => [LOWER_CONSONANTS],
        'C' => [LOWER_CONSONANTS, UPPER_CONSONANTS],
        'z' => [UPPER_CONSONANTS],
        'd' => [DIGITS],
        'h' => [LOWER_HEX],
        'H' => [UPPER_HEX],
        'l' => [LOWERCASE],
        'L' => [LOWERCASE, UPPERCASE],
        'u' => [UPPERCASE],
        'p' => [PUNCTUATION],
        'b' => [BRACKETS],
        's' => [PRINTABLE_ASCII_SPECIAL],
        'S' => [UPPERCASE, LOWERCASE, DIGITS, PRINTABLE_ASCII_SPECIAL],
        'v' => [LOWER_VOWELS],
        'V' => [LOWER_VOWELS, UPPER_VOWELS],
        'Z' => [UPPER_VOWELS],
        'x' => [HIGH_ANSI],
      }
      
      ASCII_MAPPING = DEFAULT_MAPPING.reject { |k, v| k == 'x' }
      
      # @return [Hash] the KeePass character set ID mapping
      attr_accessor :mapping
      
      # Instantiates a new CharSet object.
      #
      # @see Set#new
      def initialize(*args)
        @mapping = DEFAULT_MAPPING
        super
      end

      # Adds several characters according to the KeePass character class.
      #
      # @see http://keepass.info/help/base/pwgenerator.html#pattern
      # @param [String] char_set_id the KeePass character set ID
      # @raise [InvalidCharSetIDError] if mapping does not contain `char_set_id`
      # @return [CharSet] self
      def add_from_char_set_id(char_set_id)
        if strings = mapping[char_set_id]
          add_from_strings *strings
        else
          raise InvalidCharSetIDError, "no such char set ID #{char_set_id.inspect}"
        end
      end
  
      # Adds each character from one or more strings.
      #
      # @param [Array] *strings one or more strings to add
      # @return [CharSet] self
      def add_from_strings(*strings)
        strings.each { |s| merge Set.new(s.split('')) }
        self
      end
  
    end

  end

end
