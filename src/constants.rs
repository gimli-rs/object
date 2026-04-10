#[cfg(feature = "names")]
use core::slice;

/// The names and values for a set of constants with a given type.
#[cfg(feature = "names")]
#[derive(Debug, Default)]
pub struct ConstantNames<T: 'static> {
    pub(crate) next: Option<&'static ConstantNames<T>>,
    pub(crate) entries: &'static [(T, &'static str)],
}

#[cfg(feature = "names")]
impl<T: 'static> ConstantNames<T> {
    pub(crate) const fn new() -> Self {
        Self {
            next: None,
            entries: &[],
        }
    }
}

#[cfg(feature = "names")]
impl<T: 'static + Copy + PartialEq> ConstantNames<T> {
    /// Get the name of the first constant with the given value.
    pub fn name(&self, value: T) -> Option<&'static str> {
        self.iter().find(|x| x.0 == value).map(|x| x.1)
    }
}

#[cfg(feature = "names")]
impl<T: 'static + Copy> ConstantNames<T> {
    /// Iterate over the names and values for all constants in the set.
    pub fn iter(&self) -> ConstantNameIter<T> {
        ConstantNameIter {
            next: self.next,
            entries: self.entries.iter(),
        }
    }
}

/// An iterator for the values and names in a [`ConstantNames`].
#[cfg(feature = "names")]
#[derive(Debug)]
pub struct ConstantNameIter<T: 'static> {
    pub(crate) next: Option<&'static ConstantNames<T>>,
    pub(crate) entries: slice::Iter<'static, (T, &'static str)>,
}

#[cfg(feature = "names")]
impl<T: 'static + Copy> Iterator for ConstantNameIter<T> {
    type Item = (T, &'static str);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(item) = self.entries.next().copied() {
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
#[cfg(feature = "names")]
#[derive(Debug, Default)]
pub struct FlagNames<T: 'static> {
    pub(crate) next: Option<&'static FlagNames<T>>,
    /// Independent bit flags.
    pub(crate) bits: &'static [(T, &'static str)],
    /// Masked groups.
    pub(crate) groups: &'static [FlagGroup<T>],
}

#[cfg(feature = "names")]
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
#[cfg(feature = "names")]
#[derive(Debug)]
pub struct FlagBitsIter<T: 'static> {
    next: Option<&'static FlagNames<T>>,
    bits: slice::Iter<'static, (T, &'static str)>,
}

#[cfg(feature = "names")]
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
#[cfg(feature = "names")]
#[derive(Debug)]
pub struct FlagGroupsIter<T: 'static> {
    next: Option<&'static FlagNames<T>>,
    groups: slice::Iter<'static, FlagGroup<T>>,
}

#[cfg(feature = "names")]
impl<T: 'static + Copy> Iterator for FlagGroupsIter<T> {
    type Item = &'static FlagGroup<T>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(item) = self.groups.next() {
                return Some(item);
            }
            *self = self.next?.groups_iter();
        }
    }
}

/// A masked group of entries in a [`FlagNames`].
///
/// An entry is set when `(value & mask) == sub_value`
#[cfg(feature = "names")]
#[derive(Debug)]
pub struct FlagGroup<T: 'static> {
    pub(crate) mask: T,
    pub(crate) mask_name: Option<&'static str>,
    pub(crate) entries: &'static [(T, &'static str)],
}

#[cfg(feature = "names")]
impl<T: 'static + Copy> FlagGroup<T> {
    /// The mask to apply to a value before comparing to entries.
    pub fn mask(&self) -> T {
        self.mask
    }

    /// The name of the mask constant, if any.
    pub fn mask_name(&self) -> Option<&'static str> {
        self.mask_name
    }

    /// The values and names for entries in this group.
    pub fn entries(&self) -> &'static [(T, &'static str)] {
        self.entries
    }

    /// Get the name of the first entry with the given value.
    ///
    /// The group mask will be applied to the value before comparison.
    pub fn name<U>(&self, value: U) -> Option<&'static str>
    where
        T: Into<U>,
        U: PartialEq + core::ops::BitAnd<Output = U>,
    {
        let masked = value & self.mask.into();
        self.entries
            .iter()
            .find(|(v, _)| (*v).into() == masked)
            .map(|(_, n)| *n)
    }
}

/// Define consts and values for multiple constant types.
///
/// Two forms are supported:
///
/// **Struct form** — associates blocks with a named struct implementing `constants()` and
/// `constants_value()`. The caller should have defined a `struct Constants` with matching
/// fields. An optional parent struct can be specified to inherit its blocks via `next` chaining.
/// ```text
/// constants! {
///     struct Base;             // or: struct Arch(Base);
///     consts name: type { ... }
///     flags name: type { ... }
/// }
/// ```
///
/// **Freestanding form** — generates standalone `fn` accessors without a struct.
/// ```text
/// constants! {
///     consts name: type { ... }
///     flags name: type { ... }
/// }
/// ```
///
/// Each block is prefixed with a kind:
/// - `consts name: type { NAME = value, ... }` — generates a `ConstantNames<type>`
/// - `flags name: type { ... }` — generates a `FlagNames<type>`
///
/// A masked group in a `flags` block uses `=>`. The mask name is optional:
/// ```text
/// MASK_NAME = mask_value => {
///     SUB_NAME = sub_value,
///     ...
/// },
/// mask_value => {
///     SUB_NAME = sub_value,
///     ...
/// },
/// ```
///
/// # Example
///
/// Input:
/// ```text
/// constants! {
///     struct Base;
///     consts foo: u32 {
///         FOO_A = 0,
///         FOO_B = 1,
///     }
///     flags bar: u32 {
///         FLAG_X = 0x1,
///         MASK = 0xf0 => {
///             MASK_A = 0x10,
///             MASK_B = 0x20,
///         },
///     }
/// }
///
/// constants! {
///     struct Arch(Base);
///     consts foo: u32 {
///         FOO_ARCH = 100,
///     }
/// }
///
/// constants! {
///     consts baz: u32 {
///         BAZ_X = 1,
///         BAZ_Y = 2,
///     }
/// }
/// ```
///
/// Generated:
/// ```text
/// // --- Base ---
/// #[derive(Debug, Clone, Copy)]
/// struct Base;
///
/// impl Base {
///     const fn constants_value() -> Constants {
///         Constants { foo: Self::foo(), bar: Self::bar() }
///     }
///     const fn constants() -> &'static Constants {
///         static C: Constants = Base::constants_value();
///         &C
///     }
///     const fn foo() -> &'static ConstantNames<u32> {
///         static NAMES: ConstantNames<u32> = ConstantNames {
///             next: None,
///             names: &[(0, "FOO_A"), (1, "FOO_B")],
///         };
///         &NAMES
///     }
///     const fn bar() -> &'static FlagNames<u32> {
///         static FLAG_NAMES: FlagNames<u32> = FlagNames {
///             next: None,
///             bits: &[(0x1, "FLAG_X")],
///             groups: &[FlagGroup {
///                 mask: 0xf0,
///                 mask_name: MASK,
///                 entries: &[(0x10, "MASK_A"), (0x20, "MASK_B")],
///             }],
///         };
///         &FLAG_NAMES
///     }
/// }
/// pub const FOO_A: u32 = 0;
/// pub const FOO_B: u32 = 1;
/// pub const FLAG_X: u32 = 0x1;
/// pub const MASK: u32 = 0xf0;
/// pub const MASK_A: u32 = 0x10;
/// pub const MASK_B: u32 = 0x20;
///
/// // --- Arch ---
/// #[derive(Debug, Clone, Copy)]
/// struct Arch;
///
/// impl Arch {
///     const fn constants_value() -> Constants {
///         Constants { foo: Self::foo(), ..Base::constants_value() }
///     }
///     const fn constants() -> &'static Constants {
///         static C: Constants = Arch::constants_value();
///         &C
///     }
///     // NAMES::next chains to Base::foo() so iteration returns
///     // arch-specific entries first, then Base entries.
///     const fn foo() -> &'static ConstantNames<u32> {
///         static NAMES: ConstantNames<u32> = ConstantNames {
///             next: Some(Base::foo()),
///             names: &[(100, "FOO_ARCH")],
///         };
///         &NAMES
///     }
/// }
/// pub const FOO_ARCH: u32 = 100;
///
/// // --- freestanding ---
/// const fn baz() -> &'static ConstantNames<u32> {
///     static NAMES: ConstantNames<u32> = ConstantNames {
///         next: None,
///         names: &[(1, "BAZ_X"), (2, "BAZ_Y")],
///     };
///     &NAMES
/// }
/// pub const BAZ_X: u32 = 1;
/// pub const BAZ_Y: u32 = 2;
/// ```
macro_rules! constants {
    // Struct form where methods defines constants.
    ($(#[$meta:meta])* struct $struct:ident$(($parent:ident))?;
        $($kind:ident $method:ident: $outer:ident$(($inner:ident))? {
            $($body:tt)*
        })*
    ) => {
        constants! { @struct $(#[$meta])* $struct }
        // This converts $parent into a tt so that the method repetition can use it.
        constants! { @impl_struct $struct ($($parent)?)
            $($kind $method ($outer $($inner)?) { $($body)* })*
        }
        $(constants! { @consts $kind ($outer $($inner)?) $($body)* })*
    };

    // Struct form where methods reference freestanding functions.
    ($(#[$meta:meta])* struct $struct:ident$(($parent:ident))?;
        $($kind:ident $method:ident: $type:ident = $fn:ident;)*
    ) => {
        constants! { @struct $(#[$meta])* $struct }
        constants! { @impl_struct_refs $struct ($($parent)?)
            $($kind $method $type $fn;)*
        }
    };

    // Freestanding functions.
    ($($kind:ident $fn_name:ident: $outer:ident$(($inner:ident))? { $($body:tt)* })*) => {
        #[cfg(feature = "names")]
        $(constants! { @impl_method $kind $fn_name ($outer $($inner)?) () { $($body)* }})*
        $(constants! { @consts $kind ($outer $($inner)?) $($body)* })*
    };

    (@struct $(#[$meta:meta])* $struct:ident) => {
        #[cfg(feature = "names")]
        $(#[$meta])*
        #[derive(Debug, Clone, Copy)]
        struct $struct;
    };

    // Emit impl block of the struct.
    (@impl_struct $struct:ident $parent:tt
        $($kind:ident $method:ident $type:tt {
            $($body:tt)*
        })*
    ) => {
        #[cfg(feature = "names")]
        impl $struct {
            const fn constants_value() -> Constants {
                constants!(@impl_value $parent $($method)*)
            }

            const fn constants() -> &'static Constants {
                static C: Constants = $struct::constants_value();
                &C
            }

            $(constants! { @impl_method $kind $method $type $parent {
                $($body)*
            }})*
        }
    };

    // Emit impl block for ref-style struct (delegates to freestanding functions).
    (@impl_struct_refs $struct:ident $parent:tt
        $($kind:ident $method:ident $type:ident $fn:ident;)*
    ) => {
        #[cfg(feature = "names")]
        impl $struct {
            const fn constants_value() -> Constants {
                constants!(@impl_value $parent $($method)*)
            }

            const fn constants() -> &'static Constants {
                static C: Constants = $struct::constants_value();
                &C
            }

            $(constants! { @ref_method $kind $method $type $fn })*
        }
    };

    // Emit method returning an empty ConstantNames.
    (@ref_method consts $method:ident $type:ident None) => {
        const fn $method() -> &'static crate::constants::ConstantNames<$type> {
            static NAMES: crate::constants::ConstantNames<$type> =
                crate::constants::ConstantNames { next: None, entries: &[] };
            &NAMES
        }
    };

    // Emit method returning an empty FlagNames.
    (@ref_method flags $method:ident $type:ident None) => {
        const fn $method() -> &'static crate::constants::FlagNames<$type> {
            static FLAG_NAMES: crate::constants::FlagNames<$type> =
                crate::constants::FlagNames { next: None, bits: &[], groups: &[] };
            &FLAG_NAMES
        }
    };

    // Emit method that delegates to a freestanding consts function.
    (@ref_method consts $method:ident $type:ident $fn:ident) => {
        const fn $method() -> &'static crate::constants::ConstantNames<$type> {
            $fn()
        }
    };

    // Emit method that delegates to a freestanding flags function.
    (@ref_method flags $method:ident $type:ident $fn:ident) => {
        const fn $method() -> &'static crate::constants::FlagNames<$type> {
            $fn()
        }
    };

    // Emit body of `constants_value`
    (@impl_value () $($method:ident)*) => {
        Constants {
            $($method: Self::$method(),)*
        }
    };
    (@impl_value ($parent:ident) $($method:ident)*) => {
        #[allow(clippy::needless_update)]
        Constants {
            $($method: Self::$method(),)*
            ..$parent::constants_value()
        }
    };

    // Emit value of `ConstantNames::next` or `FlagNames::next`
    (@impl_next $method:ident ()) => { None };
    (@impl_next $method:ident ($parent:ident)) => { Some($parent::$method()) };

    (@type ($outer:ident $inner:ident)) => { $outer };
    (@type ($type:ident)) => { $type };
    (@value ($outer:ident $inner:ident) $value:expr) => { $outer($value) };
    (@value ($type:ident) $value:expr) => { $value };

    // Emit ConstantNames static for a `consts` block
    (@impl_method consts $method:ident $type:tt $parent:tt {
        $($(#[$const_meta:meta])* $name:ident = $value:expr),* $(,)?
    }) => {
        const fn $method() -> &'static crate::constants::ConstantNames<constants!(@type $type)> {
            static NAMES: crate::constants::ConstantNames<constants!(@type $type)> = crate::constants::ConstantNames {
                next: constants!(@impl_next $method $parent),
                entries: &[$((constants!(@value $type $value), stringify!($name)),)*],
            };
            &NAMES
        }
    };

    // Emit FlagNames static for a `flags` block (via tt-munching)
    (@impl_method flags $method:ident $type:tt $parent:tt {
        $($body:tt)*
    }) => {
        const fn $method() -> &'static crate::constants::FlagNames<constants!(@type $type)> {
            constants! { @flags_static $method $type $parent [] [] $($body)* }
            &FLAG_NAMES
        }
    };

    // tt-muncher: build the FlagNames static
    // Accumulators: [bits...] [groups...]

    // Terminal: emit the static
    (@flags_static $method:ident $type:tt $parent:tt [$($bits:tt)*] [$($groups:tt)*]) => {
        static FLAG_NAMES: crate::constants::FlagNames<constants!(@type $type)> = crate::constants::FlagNames {
            next: constants!(@impl_next $method $parent),
            bits: &[$($bits)*],
            groups: &[$($groups)*],
        };
    };

    // Bit entry (NAME = VAL,)
    (@flags_static $method:ident $type:tt $parent:tt [$($bits:tt)*] [$($groups:tt)*]
        $(#[$_meta:meta])* $name:ident = $value:expr,
        $($rest:tt)*
    ) => {
        constants! {
            @flags_static $method $type $parent
            [$($bits)* (constants!(@value $type $value), stringify!($name)),]
            [$($groups)*]
            $($rest)*
        }
    };

    // Group entry (NAME = MASK => { ... },)
    (@flags_static $method:ident $type:tt $parent:tt [$($bits:tt)*] [$($groups:tt)*]
        $(#[$_meta:meta])* $name:ident = $value:expr => {
            $($(#[$_smeta:meta])* $sub_name:ident = $sub_value:expr),* $(,)?
        },
        $($rest:tt)*
    ) => {
        constants! {
            @flags_static $method $type $parent
            [$($bits)*]
            [$($groups)* (crate::constants::FlagGroup {
                mask: constants!(@value $type $value),
                mask_name: Some(stringify!($name)),
                entries: &[$( (constants!(@value $type $sub_value), stringify!($sub_name)), )*],
            }),]
            $($rest)*
        }
    };

    // Nameless group entry (MASK => { ... },)
    (@flags_static $method:ident $type:tt $parent:tt [$($bits:tt)*] [$($groups:tt)*]
        $value:expr => {
            $($(#[$_smeta:meta])* $sub_name:ident = $sub_value:expr),* $(,)?
        },
        $($rest:tt)*
    ) => {
        constants! {
            @flags_static $method $type $parent
            [$($bits)*]
            [$($groups)* (crate::constants::FlagGroup {
                mask: constants!(@value $type $value),
                mask_name: None,
                entries: &[$( (constants!(@value $type $sub_value), stringify!($sub_name)), )*],
            }),]
            $($rest)*
        }
    };

    // Emit pub consts for a `consts` block.
    (@consts consts $type:tt
        $($(#[$meta:meta])* $name:ident = $value:expr),* $(,)?
    ) => {
        $($(#[$meta])* pub const $name: constants!(@type $type) = constants!(@value $type $value);)*
    };

    // Emit pub consts for a `flags` block (via tt-munching, to handle nameless groups).
    (@consts flags $type:tt $($body:tt)*) => {
        constants! { @flags_consts $type $($body)* }
    };

    // tt-muncher: emit pub consts for a `flags` block

    // Terminal
    (@flags_consts $type:tt) => {};

    // Bit entry (NAME = VAL,)
    (@flags_consts $type:tt
        $(#[$meta:meta])* $name:ident = $value:expr,
        $($rest:tt)*
    ) => {
        $(#[$meta])* pub const $name: constants!(@type $type) = constants!(@value $type $value);
        constants! { @flags_consts $type $($rest)* }
    };

    // Named group entry (NAME = MASK => { ... },)
    (@flags_consts $type:tt
        $(#[$meta:meta])* $name:ident = $value:expr => {
            $($(#[$smeta:meta])* $sub_name:ident = $sub_value:expr),* $(,)?
        },
        $($rest:tt)*
    ) => {
        $(#[$meta])* pub const $name: constants!(@type $type) = constants!(@value $type $value);
        $($(#[$smeta])* pub const $sub_name: constants!(@type $type) = constants!(@value $type $sub_value);)*
        constants! { @flags_consts $type $($rest)* }
    };

    // Nameless group entry (MASK => { ... },)
    (@flags_consts $type:tt
        $value:expr => {
            $($(#[$smeta:meta])* $sub_name:ident = $sub_value:expr),* $(,)?
        },
        $($rest:tt)*
    ) => {
        $($(#[$smeta])* pub const $sub_name: constants!(@type $type) = constants!(@value $type $sub_value);)*
        constants! { @flags_consts $type $($rest)* }
    };
}
pub(crate) use constants;
