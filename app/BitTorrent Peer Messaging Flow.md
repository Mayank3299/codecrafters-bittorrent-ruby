You                             Peer
 |                                |
 |--- Handshake ----------------->|
 |<-- Handshake ------------------|
 |                                |
 |<-- Bitfield / Have ------------|  (shows what pieces the peer has)
 |                                |
 |--- Interested ---------------->|
 |<-- Unchoke --------------------|
 |                                |
 |--- Request (piece X, block Y)->|
 |<-- Piece (X, block Y) ---------|
 |                                |
 |--- Request (next block) ------>|
 |<-- Piece ----------------------|
 |                                |
 |--- Have (piece completed) ---->|  (optional: tells peer what you now have)
 |                                |
 |--- Keep-Alive ---------------->|  (if idle for ~2 mins)
 |<-- Keep-Alive -----------------|
 |                                |
 |--- Not Interested ------------>|  (optional, if you don't need any more)
 |<-- Choke ----------------------|  (optional, if peer wants to stop serving)