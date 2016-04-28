FlowRadr
========

## Build

    cd targets/simple_router/flow_radar_bm
    make
    cd ..
    make bm
    cd flow_radar_bm
    python change.py
    cd ..  
    make bm

## run

    cd tests/control

change the paths in flow_radar/config.json to the right path in your system.

    sudo python -m flow_radar.topo

In another terminal, use the following command to get the flow_radar data from switch

    python -m flow_radar.get_flow_radar

