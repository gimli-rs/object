use core::slice;

/// The names and values for a set of constants with a given type.
#[derive(Debug, Default)]
pub struct ConstantNames<T: 'static> {
    pub(crate) next: Option<&'static ConstantNames<T>>,
    pub(crate) names: &'static [(T, &'static str)],
}

impl<T: 'static + Copy + PartialEq> ConstantNames<T> {
    /// Get the name of the first constant with the given value.
    pub fn name(&self, value: T) -> Option<&'static str> {
        self.iter().find(|x| x.0 == value).map(|x| x.1)
    }
}

impl<T: 'static + Copy> ConstantNames<T> {
    /// Iterate over the names and values for all constants in the set.
    pub fn iter(&self) -> ConstantNameIter<T> {
        ConstantNameIter {
            next: self.next,
            names: self.names.iter(),
        }
    }
}

/// An iterator for the values and names in a [`ConstantNames`].
#[derive(Debug)]
pub struct ConstantNameIter<T: 'static> {
    pub(crate) next: Option<&'static ConstantNames<T>>,
    pub(crate) names: slice::Iter<'static, (T, &'static str)>,
}

impl<T: 'static + Copy> Iterator for ConstantNameIter<T> {
    type Item = (T, &'static str);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(item) = self.names.next().copied() {
                return Some(item);
            }
            *self = self.next?.iter();
        }
    }
}

/// The names and values for flags in a bitfield.
///
/// Contains two kinds of entries:
/// - Independent bits: set when `(value & bit) == bit`
/// - Masked groups: set when `(value & mask) == sub_value`
#[derive(Debug, Default)]
pub struct FlagNames<T: 'static> {
    pub(crate) next: Option<&'static FlagNames<T>>,
    /// Independent bit flags.
    pub(crate) bits: &'static [(T, &'static str)],
    /// Masked groups: (mask, [(sub_value, sub_name)]).
    pub(crate) groups: &'static [(T, &'static [(T, &'static str)])],
}

impl<T: 'static + Copy> FlagNames<T> {
    /// Iterate over all bit entries.
    pub fn bits_iter(&self) -> FlagBitsIter<T> {
        FlagBitsIter {
            next: self.next,
            bits: self.bits.iter(),
        }
    }

    /// Iterate over all group entries.
    pub fn groups_iter(&self) -> FlagGroupsIter<T> {
        FlagGroupsIter {
            next: self.next,
            groups: self.groups.iter(),
        }
    }
}

/// An iterator for the bit entries in a [`FlagNames`].
#[derive(Debug)]
pub struct FlagBitsIter<T: 'static> {
    next: Option<&'static FlagNames<T>>,
    bits: slice::Iter<'static, (T, &'static str)>,
}

impl<T: 'static + Copy> Iterator for FlagBitsIter<T> {
    type Item = (T, &'static str);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(item) = self.bits.next().copied() {
                return Some(item);
            }
            *self = self.next?.bits_iter();
        }
    }
}

/// An iterator for the group entries in a [`FlagNames`].
#[derive(Debug)]
pub struct FlagGroupsIter<T: 'static> {
    next: Option<&'static FlagNames<T>>,
    groups: slice::Iter<'static, (T, &'static [(T, &'static str)])>,
}

impl<T: 'static + Copy> Iterator for FlagGroupsIter<T> {
    type Item = (T, &'static [(T, &'static str)]);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(item) = self.groups.next().copied() {
                return Some(item);
            }
            *self = self.next?.groups_iter();
        }
    }
}

/// Define consts and values for multiple constant types.
///
/// The caller should have defined a `struct Constants` with matching fields.
///
/// Each block is prefixed with a kind:
/// - `consts(method, type) { NAME = value, ... }` — generates a `ConstantNames<type>`
/// - `flags(method, type) { NAME = value, ... }` — generates a `FlagNames<type>`
///
/// A masked group in a `flags` block uses `=>`:
/// ```text
/// MASK_NAME = mask_value => {
///     SUB_NAME = sub_value,
///     ...
/// },
/// ```
macro_rules! constants {
    ($(#[$meta:meta])* $struct:ident $($rest:tt)*) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy)]
        struct $struct;

        constants!(@inject_parent $struct $($rest)*);
    };

    // ConstantNames::next needs to be either None or Some($parent::$method()). We can't
    // use a repetition of $parent because that would be a different repetition level from
    // $method, so we need to inject $parent into the $method repetition. For convenience,
    // we inject as a parent/method pair.
    (@inject_parent $struct:ident($parent:ident)
        $(, $kind:ident($method:ident, $type:ident) {
            $($body:tt)*
        })* $(,)?
    ) => {
        constants!(@impl $struct($parent),
            $($kind($method, $type $parent $method) {
                $($body)*
            }),*
        );
    };
    (@inject_parent $struct:ident $($rest:tt)*) => {
        constants!(@impl $struct() $($rest)*);
    };

    (@impl $struct:ident($($parent:tt)*),
        $($kind:ident($method:ident, $type:ident $($next:tt)*) {
            $($body:tt)*
        }),* $(,)?
    ) => {
        impl $struct {
            const fn constants_value() -> Constants {
                constants!(@impl_value $struct($($parent)*) $($method)*)
            }

            pub const fn constants() -> &'static Constants {
                static C: Constants = $struct::constants_value();
                &C
            }
        }

        $(constants!(@emit $kind $struct $method $type ($($next)*) {
            $($body)*
        });)*
    };

    // Emit body of `constants_value`
    (@impl_value $struct:ident() $($method:ident)*) => {
        Constants {
            $($method: $struct::$method(),)*
        }
    };
    (@impl_value $struct:ident($parent:ident) $($method:ident)*) => {
        Constants {
            $($method: $struct::$method(),)*
            ..$parent::constants_value()
        }
    };

    // Emit ConstantNames static + pub consts for a `consts` block
    (@emit consts $struct:ident $method:ident $type:ident ($($next:tt)*) {
        $($(#[$const_meta:meta])* $name:ident = $value:expr),* $(,)?
    }) => {
        impl $struct {
            const fn $method() -> &'static crate::constants::ConstantNames<$type> {
                static NAMES: crate::constants::ConstantNames<$type> = crate::constants::ConstantNames {
                    next: constants!(@emit_next $($next)*),
                    names: &[
                        $(($name, stringify!($name)),)*
                    ],
                };
                &NAMES
            }
        }

        $(
            $(#[$const_meta])*
            pub const $name: $type = $value;
        )*
    };

    // Emit FlagNames static + pub consts for a `flags` block (via tt-munching)
    (@emit flags $struct:ident $method:ident $type:ident ($($next:tt)*) {
        $($body:tt)*
    }) => {
        impl $struct {
            const fn $method() -> &'static crate::constants::FlagNames<$type> {
                constants!(@flags_static $type ($($next)*) [] [] $($body)*);
                &FLAG_NAMES
            }
        }

        constants!(@flags_consts $type $($body)*);
    };

    // tt-muncher: build the FlagNames const
    // Accumulators: [bits...] [groups...]

    // Terminal: emit the const
    (@flags_static $type:ident ($($next:tt)*) [$($bits:tt)*] [$($groups:tt)*]) => {
        static FLAG_NAMES: crate::constants::FlagNames<$type> = crate::constants::FlagNames {
            next: constants!(@emit_next $($next)*),
            bits: &[$($bits)*],
            groups: &[$($groups)*],
        };
    };

    // Bit entry (NAME = VAL,)
    (@flags_static $type:ident ($($next:tt)*) [$($bits:tt)*] [$($groups:tt)*]
        $(#[$_meta:meta])* $name:ident = $value:expr , $($rest:tt)*
    ) => {
        constants!(@flags_static $type ($($next)*)
            [$($bits)* ($value, stringify!($name)),]
            [$($groups)*]
            $($rest)*
        );
    };

    // Group entry (NAME = MASK => { ... },)
    (@flags_static $type:ident ($($next:tt)*) [$($bits:tt)*] [$($groups:tt)*]
        $(#[$_meta:meta])* $name:ident = $value:expr => {
            $($(#[$_smeta:meta])* $sub_name:ident = $sub_value:expr),* $(,)?
        } , $($rest:tt)*
    ) => {
        constants!(@flags_static $type ($($next)*)
            [$($bits)*]
            [$($groups)* ($value, &[$( ($sub_value, stringify!($sub_name)), )*]),]
            $($rest)*
        );
    };

    // tt-muncher: emit pub consts for a `flags` block

    (@flags_consts $type:ident) => {};

    // Bit entry (NAME = VAL,)
    (@flags_consts $type:ident
        $(#[$meta:meta])* $name:ident = $value:expr , $($rest:tt)*
    ) => {
        $(#[$meta])*
        pub const $name: $type = $value;
        constants!(@flags_consts $type $($rest)*);
    };

    // Group entry (NAME = MASK => { ... },)
    (@flags_consts $type:ident
        $(#[$meta:meta])* $name:ident = $value:expr => {
            $($(#[$smeta:meta])* $sub_name:ident = $sub_value:expr),* $(,)?
        } , $($rest:tt)*
    ) => {
        $(#[$meta])*
        pub const $name: $type = $value;
        $(
            $(#[$smeta])*
            pub const $sub_name: $type = $sub_value;
        )*
        constants!(@flags_consts $type $($rest)*);
    };

    // Emit value of `ConstantNames::next` or `FlagNames::next`
    (@emit_next) => { None };
    (@emit_next $parent:ident $method:ident) => { Some($parent::$method()) };

}
pub(crate) use constants;
