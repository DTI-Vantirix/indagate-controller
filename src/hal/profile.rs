use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct GpioLine {
    pub chip: &'static str,
    pub line: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReaderProfile {
    pub channel: u8,
    pub d0: GpioLine,
    pub d1: GpioLine,
    pub led: GpioLine,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoorProfile {
    pub channel: u8,
    pub contact: GpioLine,
    pub rex: GpioLine,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelayProfile {
    pub channel: u8,
    pub chip: &'static str,
    pub line: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct BoardProfile {
    pub model: &'static str,
    pub doors: Vec<DoorProfile>,
    pub readers: Vec<ReaderProfile>,
    pub relays: Vec<RelayProfile>,
    pub fire: GpioLine,
    pub rs485_device: &'static str,
}

pub fn acp4wr6_r1() -> BoardProfile {
    BoardProfile {
        model: "HNX-HW-SP-ACP4WR6-R1",

        doors: vec![
            DoorProfile {
                channel: 0,
                contact: GpioLine {
                    chip: "gpiochip4",
                    line: 12,
                },
                rex: GpioLine {
                    chip: "gpiochip4",
                    line: 13,
                },
            },
            DoorProfile {
                channel: 1,
                contact: GpioLine {
                    chip: "gpiochip0",
                    line: 8,
                },
                rex: GpioLine {
                    chip: "gpiochip0",
                    line: 1,
                },
            },
            DoorProfile {
                channel: 2,
                contact: GpioLine {
                    chip: "gpiochip4",
                    line: 28,
                },
                rex: GpioLine {
                    chip: "gpiochip0",
                    line: 14,
                },
            },
            DoorProfile {
                channel: 3,
                contact: GpioLine {
                    chip: "gpiochip4",
                    line: 29,
                },
                rex: GpioLine {
                    chip: "gpiochip3",
                    line: 22,
                },
            },
        ],

        readers: vec![
            ReaderProfile {
                channel: 0,
                d0: GpioLine {
                    chip: "gpiochip3",
                    line: 23,
                },
                d1: GpioLine {
                    chip: "gpiochip3",
                    line: 25,
                },
                led: GpioLine {
                    chip: "gpiochip1",
                    line: 13,
                },
            },
            ReaderProfile {
                channel: 1,
                d0: GpioLine {
                    chip: "gpiochip3",
                    line: 26,
                },
                d1: GpioLine {
                    chip: "gpiochip0",
                    line: 15,
                },
                led: GpioLine {
                    chip: "gpiochip1",
                    line: 17,
                },
            },
            ReaderProfile {
                channel: 2,
                d0: GpioLine {
                    chip: "gpiochip4",
                    line: 10,
                },
                d1: GpioLine {
                    chip: "gpiochip4",
                    line: 26,
                },
                led: GpioLine {
                    chip: "gpiochip1",
                    line: 15,
                },
            },
            ReaderProfile {
                channel: 3,
                d0: GpioLine {
                    chip: "gpiochip4",
                    line: 27,
                },
                d1: GpioLine {
                    chip: "gpiochip4",
                    line: 11,
                },
                led: GpioLine {
                    chip: "gpiochip1",
                    line: 16,
                },
            },
        ],

        relays: vec![
            RelayProfile {
                channel: 0,
                chip: "pca9534",
                line: 4,
            },
            RelayProfile {
                channel: 1,
                chip: "pca9534",
                line: 5,
            },
            RelayProfile {
                channel: 2,
                chip: "pca9534",
                line: 6,
            },
            RelayProfile {
                channel: 3,
                chip: "pca9534",
                line: 7,
            },
        ],

        fire: GpioLine {
            chip: "gpiochip3",
            line: 21,
        },

        rs485_device: "/dev/ttymxc0",
    }
}
