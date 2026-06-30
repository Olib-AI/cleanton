#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EasingFunction {
    Linear,
    EaseInOut,
    EaseOutCubic,
    Spring { stiffness: f32, damping: f32 },
}

#[derive(Debug, Clone)]
pub struct AnimatedValue {
    current: f32,
    target: f32,
    velocity: f32,
    easing: EasingFunction,
}

impl AnimatedValue {
    pub fn new(value: f32, easing: EasingFunction) -> Self {
        Self {
            current: value,
            target: value,
            velocity: 0.0,
            easing,
        }
    }

    pub fn set_target(&mut self, target: f32) {
        self.target = target;
    }

    pub fn current(&self) -> f32 {
        self.current
    }

    pub fn target(&self) -> f32 {
        self.target
    }

    pub fn tick(&mut self, dt: f32) {
        match self.easing {
            EasingFunction::Linear => {
                let diff = self.target - self.current;
                let step = 5.0 * dt; // speed factor
                if diff.abs() < step {
                    self.current = self.target;
                } else {
                    self.current += diff.signum() * step;
                }
            }
            EasingFunction::EaseInOut => {
                let diff = self.target - self.current;
                self.current += diff * 10.0 * dt;
                if diff.abs() < 0.01 {
                    self.current = self.target;
                }
            }
            EasingFunction::EaseOutCubic => {
                let diff = self.target - self.current;
                self.current += diff * 15.0 * dt;
                if diff.abs() < 0.01 {
                    self.current = self.target;
                }
            }
            EasingFunction::Spring { stiffness, damping } => {
                let force = -stiffness * (self.current - self.target) - damping * self.velocity;
                self.velocity += force * dt;
                self.current += self.velocity * dt;
                if (self.current - self.target).abs() < 0.01 && self.velocity.abs() < 0.01 {
                    self.current = self.target;
                    self.velocity = 0.0;
                }
            }
        }
    }
}
