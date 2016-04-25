#include "flow_radar.h"

pthread_mutex_t flow_radar_lock;

void flow_radar_init(){
  pthread_mutex_init(&flow_radar_lock, NULL);
}

void lock_flow_radar(){
  pthread_mutex_lock(&flow_radar_lock);
}

void unlock_flow_radar(){
  pthread_mutex_unlock(&flow_radar_lock);
}
