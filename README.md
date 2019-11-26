# XNFV-SflowCollector 

Sflow Collector for XeniumNFV platform, written in GoLang using google/gopacket Library

  - Support Sflow , OpenFlow counter (counter type => 1004, 1005)
  - Support Kafka (Send each Switch Sflow data throught Kafka)

# flow OpenFlow record

  ```
  // **************************************************
//  OpenFlow Counter Record
// **************************************************
//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |           openflow datapath id  LLLLLLLL      |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |           openflow datapath id  HHHHHHHH      |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  openflow port                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

  ```

# flow OpenFlow Port record

  ```
// **************************************************
//  OpenFlow Port Name Counter Record
// **************************************************
//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                 record length                 |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   skipBytes                   |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   Port Name                   |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

  ```
