use crossterm::event::{self, Event as CrossEvent, KeyEvent};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub enum Event {
    Key(KeyEvent),
    Resize(u16, u16),
    Tick,
}

#[derive(Debug)]
pub struct EventHandler {
    tick_rate: Duration,
    last_tick: Instant,
}

impl EventHandler {
    pub fn new(tick_rate: Duration) -> Self {
        Self {
            tick_rate,
            last_tick: Instant::now(),
        }
    }

    pub fn next(&mut self) -> Result<Event, std::io::Error> {
        let timeout = self
            .tick_rate
            .checked_sub(self.last_tick.elapsed())
            .unwrap_or(Duration::from_secs(0));

        if event::poll(timeout)? {
            match event::read()? {
                CrossEvent::Key(key) => Ok(Event::Key(key)),
                CrossEvent::Resize(w, h) => Ok(Event::Resize(w, h)),
                _ => Ok(Event::Tick),
            }
        } else {
            self.last_tick = Instant::now();
            Ok(Event::Tick)
        }
    }
}
