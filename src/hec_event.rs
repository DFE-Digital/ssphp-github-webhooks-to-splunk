use serde::Serialize;
use std::fmt::Debug;

// #[derive(Serialize, Debug)]
// pub struct HecEvents<D: Serialize + Debug> {
//     events: Vec<HecEvent<D>>,
// }

// impl<D: Serialize + Debug> HecEvents<D> {
//     pub fn new() -> HecEvents<D> {
//         HecEvents{
//             events: Vec::new(),
//         }
//     }

//     pub fn add_hec_event(&mut self, hec_event: HecEvent<D>) {
//         self.events.push(hec_event);
//     }

//     pub fn format_data(self) -> Vec<String> {

//         let mut serialized_events = Vec::new();

//         for event in self.events {
//             let serialized_event = serde_json::to_string_pretty(&event).unwrap();

//             serialized_events.push(serialized_event);
//         }

//         serialized_events
//     }

// }

#[derive(Serialize, Debug)]
pub struct HecEvent<D: Serialize + Debug> {
    event: D,
    #[serde(flatten)]
    event_metadata: EventMetaData,
}

impl<D: Serialize + Debug> HecEvent<D> {
    pub fn new(event: D, event_metadata: EventMetaData) -> HecEvent<D> {
        HecEvent {
            event,
            event_metadata,
        }
    }
}

#[derive(Serialize, Debug)]
pub struct EventMetaData {
    time: usize,
    index: String,
    sourcetype: String,
    source: String,
    host: String,
}

impl EventMetaData {
    pub fn new(
        epoch_time: usize,
        index: String,
        sourcetype: String,
        source: String,
        host: String,
    ) -> EventMetaData {
        EventMetaData {
            time: epoch_time,
            index,
            sourcetype,
            source,
            host,
        }
    }
}
