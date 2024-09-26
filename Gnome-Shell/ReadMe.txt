Gnome Shell Installation:

Edit src/Conf.py to change the path to the log files.
Edit the network-neighbor.desktop file and set the path to the NetNeighbors.py file and the default interface.
Then make a symbolic link:
ln -s absolute-path-to-network-neighbor.desktop ~/.local/share/applications/network-neighbor.desktop 

