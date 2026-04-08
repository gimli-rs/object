// Make macros available without import.
// This simplifies the recursive macro usage. Without it we would either need to use
// full paths in the recursive calls or import the macros manually.
#![macro_use]
#![cfg_attr(not(feature = "read"), allow(unused_macros))]

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
    /// Get the entry at the given index.
    pub fn entry(&self, index: usize) -> Option<(T, &'static str)>
    where
        T: Copy,
    {
        match self.entries.get(index) {
            Some(entry) => Some(*entry),
            None => self.next?.entry(index - self.entries.len()),
        }
    }

    /// Get the name of the first constant with the given value.
    pub fn name(&self, value: T) -> Option<&'static str>
    where
        T: Copy + PartialEq,
    {
        self.iter().find(|x| x.0 == value).map(|x| x.1)
    }

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
impl<T: 'static> FlagNames<T> {
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
    pub(crate) names: &'static ConstantNames<T>,
}

#[cfg(feature = "names")]
impl<T: 'static> FlagGroup<T> {
    /// The mask to apply to a value before comparing to entries.
    pub fn mask(&self) -> T
    where
        T: Copy,
    {
        self.mask
    }

    /// Get the entry at the given index.
    pub fn entry(&self, index: usize) -> Option<(T, &'static str)>
    where
        T: Copy,
    {
        self.names.entry(index)
    }

    /// Get the name of the first entry with the given value.
    ///
    /// The group mask will be applied to the value before comparison.
    pub fn name<U>(&self, value: U) -> Option<&'static str>
    where
        T: Copy + Into<U>,
        U: PartialEq + core::ops::BitAnd<Output = U>,
    {
        let masked = value & self.mask.into();
        self.iter()
            .find(|(v, _)| (*v).into() == masked)
            .map(|(_, n)| n)
    }

    /// Iterate over all `(value, name)` pairs in this group.
    pub fn iter(&self) -> FlagGroupIter<T> {
        FlagGroupIter {
            names: self.names,
            index: 0,
        }
    }
}

/// An iterator over the entries of a [`FlagGroup`].
#[cfg(feature = "names")]
#[derive(Debug, Clone)]
pub struct FlagGroupIter<T: 'static> {
    names: &'static ConstantNames<T>,
    index: usize,
}

#[cfg(feature = "names")]
impl<T: Copy + 'static> Iterator for FlagGroupIter<T> {
    type Item = (T, &'static str);

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.names.entry(self.index)?;
        self.index += 1;
        Some(entry)
    }
}

/// Define a set of related constant definitions, such as for an architecture.
///
/// Defines a struct with method `constants` that returns a `struct Constants` containing
/// fields set to the given definitions. The caller should have defined `struct Constants`
/// with matching fields.
///
/// An optional parent struct can be specified to inherit definitions via `next` chaining.
/// For example, if `Base` is the parent then `consts name: type = { ... };` is expanded
/// similar to `constant_names!(name: type = Base::constants_value().name + { ... })`.
/// The parent is often a set of constant definitions that are common to all architectures.
///
/// Usage:
/// ```text
/// constants! {
///     struct Base;             // or: struct Arch(Base);
///     // Expands using constant_names!()
///     consts name: type = { ... };
///     // Expands using flag_names!()
///     flags name: type = { ... };
///     // Reference constants defined elsewhere.
///     consts name: type = VAR;
/// }
/// ```
macro_rules! constants {
    ($(#[$meta:meta])* struct $struct:ident$(($parent:ident))?;
        $($kind:ident $method:ident: $type:ident = $body:tt;)*
    ) => {
        #[cfg(feature = "names")]
        $(#[$meta])*
        #[derive(Debug, Clone, Copy)]
        struct $struct;

        #[cfg(feature = "names")]
        impl $struct {
            const fn constants_value() -> Constants {
                #[allow(clippy::needless_update)]
                Constants {
                    $($method: constants!(@ref $method $body),)*
                    $(..$parent::constants_value())?
                }
            }

            // Not used for inheritance-only structs.
            #[allow(unused)]
            const fn constants() -> &'static Constants {
                static C: Constants = $struct::constants_value();
                &C
            }

            // This converts $parent into a tt so that the method repetition can use it.
            constants! { @impl_methods ($($parent)?) $($kind $method $type $body)* }
        }

        $(constants! { @consts $kind $type $body })*
    };

    (@impl_methods $parent:tt $($kind:ident $method:ident $type:ident $body:tt)*) => {
        $(constants! { @impl_method $kind $method $type $parent $body })*
    };

    // Struct method returning ConstantNames/FlagNames static.
    // These methods exist only to give a place to define the statics,
    // so not needed for delegation.
    (@impl_method $kind:ident $method:ident $type:ident $parent:tt $fn:ident) => {};
    (@impl_method consts $method:ident $type:ident $parent:tt $body:tt) => {
        const fn $method() -> &'static crate::constants::ConstantNames<$type> {
            constant_names!(
                @static NAMES $type (constants!(@impl_next $method $parent)) $body
            );
            &NAMES
        }
    };
    (@impl_method flags $method:ident $type:ident $parent:tt $body:tt) => {
        const fn $method() -> &'static crate::constants::FlagNames<$type> {
            flag_names!(
                @static NAMES $type (constants!(@impl_next $method $parent)) $body
            );
            &NAMES
        }
    };

    // Value of `ConstantNames::next` or `FlagNames::next`.
    (@impl_next $method:ident ()) => { None };
    (@impl_next $method:ident ($parent:ident)) => { Some($parent::constants_value().$method) };

    // Value of a field in `Constants`.
    (@ref $method:ident $fn:ident) => { &$fn };
    (@ref $method:ident $body:tt) => { Self::$method() };

    // `pub const` values if required.
    (@consts $kind:tt $type:ident $fn:ident) => {};
    (@consts consts $type:ident $body:tt) => { constant_names! { @consts $type $body } };
    (@consts flags $type:ident $body:tt) => { flag_names! { @consts $type $body } };
}

/// Create a static `ConstantNames` definition, and `pub const` definitions for the values.
///
/// Usage:
/// ```text
/// constant_names!(varname: type = { NAME = value, ... });
/// ```
///
/// Extend another `ConstantNames`:
/// ```text
/// constant_names!(varname: type = NAMES + { NAME = value, ... });
/// ```
macro_rules! constant_names {
    ($varname:ident: $type:ident = $($next:ident +)? { $($body:tt)* }) => {
        constant_names! { @static $varname $type (constant_names!(@next $($next)?)) { $($body)* } }
        constant_names! { @consts $type { $($body)* } }
    };
    (@next) => { None };
    (@next $next:ident) => { Some(&$next) };
    (@static $varname:ident $type:ident ($next:expr) {
        $($(#[$meta:meta])* $name:ident = $value:expr),* $(,)?
    }) => {
        #[cfg(feature = "names")]
        static $varname: crate::constants::ConstantNames<$type> = crate::constants::ConstantNames {
            next: $next,
            entries: &[$(($value, stringify!($name)),)*],
        };
    };
    (@consts $type:ident {
        $($(#[$meta:meta])* $name:ident = $value:expr),* $(,)?
    }) => {
        $($(#[$meta])* pub const $name: $type = $value;)*
    };
}

/// Create a static `FlagNames` definition, and `pub const` definitions for the values.
///
/// Usage:
/// ```text
/// flag_names!(varname: type = { NAME = value, ... });
/// ```
///
/// Extend another `FlagNames`
/// ```text
/// flag_names!(varname: type = NAMES + { NAME = value, ... });
/// ```
///
/// Specify a subfield using a mask and a `ConstantNames` for the subfield values:
/// ```text
/// MASK_NAME = mask_value => NAMES,
/// ```
///
/// The mask name is optional:
/// ```text
/// _ = mask_value => NAMES,
/// ```
macro_rules! flag_names {
    ($varname:ident: $type:ident = $($next:ident +)? { $($body:tt)* }) => {
        flag_names! { @static $varname $type (flag_names!(@next $($next)?)) { $($body)* } }
        flag_names! { @consts $type { $($body)* } }
    };
    (@next) => { None };
    (@next $next:ident) => { Some(&$next) };
    (@static $varname:ident $type:ident ($next:expr) { $($body:tt)* }) => {
        #[cfg(feature = "names")]
        static $varname: crate::constants::FlagNames<$type> = flag_names! {
            @build_static ($type $next) [] [] $($body)*
        };
    };
    (@consts $type:ident { $($body:tt)* }) => {
        flag_names! { @build_consts $type $($body)* }
    };

    // Terminal: emit the value
    (@build_static ($type:ident $next:expr) [$($bits:tt)*] [$($groups:tt)*]) => {
        crate::constants::FlagNames {
            next: $next,
            bits: &[$($bits)*],
            groups: &[$($groups)*],
        }
    };

    // Bit entry (NAME = VAL,)
    (@build_static $args:tt [$($bits:tt)*] [$($groups:tt)*]
        $(#[$_meta:meta])* $name:ident = $value:expr,
        $($rest:tt)*
    ) => {
        flag_names! {
            @build_static $args
            [$($bits)* ($value, stringify!($name)),]
            [$($groups)*]
            $($rest)*
        }
    };

    // Group entry (NAME = MASK => { ... },)
    (@build_static ($type:ident $next:expr) [$($bits:tt)*] [$($groups:tt)*]
        $(#[$_meta:meta])* $name:ident = $value:expr => $entry:expr,
        $($rest:tt)*
    ) => {
        flag_names! {
            @build_static ($type $next)
            [$($bits)*]
            [$($groups)* (crate::constants::FlagGroup {
                mask: $value,
                names: &$entry,
            }),]
            $($rest)*
        }
    };

    // Nameless group entry (_ = MASK => { ... },)
    (@build_static ($type:ident $next:expr) [$($bits:tt)*] [$($groups:tt)*]
        _ = $value:expr => $entry:expr,
        $($rest:tt)*
    ) => {
        flag_names! {
            @build_static ($type $next)
            [$($bits)*]
            [$($groups)* (crate::constants::FlagGroup {
                mask: $value,
                names: &$entry,
            }),]
            $($rest)*
        }
    };

    // Terminal
    (@build_consts $type:ident) => {};

    // Bit entry (NAME = VAL,)
    (@build_consts $type:ident
        $(#[$meta:meta])* $name:ident = $value:expr,
        $($rest:tt)*
    ) => {
        $(#[$meta])* pub const $name: $type = $value;
        flag_names! { @build_consts $type $($rest)* }
    };

    // Named group entry (NAME = MASK => { ... },)
    (@build_consts $type:ident
        $(#[$meta:meta])* $name:ident = $value:expr => $entry:expr,
        $($rest:tt)*
    ) => {
        $(#[$meta])* pub const $name: $type = $value;
        flag_names! { @build_consts $type $($rest)* }
    };

    // Nameless group entry (_ = MASK => { ... },)
    (@build_consts $type:ident
        _ = $value:expr => $entry:expr,
        $($rest:tt)*
    ) => {
        flag_names! { @build_consts $type $($rest)* }
    };
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "names")]
    use super::{ConstantNames, FlagNames};

    /// Example macro usage.
    ///
    /// Expand with:
    /// cargo expand constants::tests --lib --tests --features names
    #[test]
    #[allow(unused)]
    fn macros() {
        constant_names!(FOO: u32 = {
            FOO_A = 0,
            FOO_B = 1,
        });
        constant_names!(BAR_FIELD_BASE: u32 = {
            BAR_A = 0x10,
            BAR_B = 0x20,
            BAR_C = 0x30,
        });
        constant_names!(BAR_FIELD: u32 = BAR_FIELD_BASE + {
            BAR_D = 0x40,
        });
        constant_names!(BAZ_FIELD: u32 = {
            BAZ_A = 0x100,
            BAZ_B = 0x200,
        });
        flag_names!(BAR: u32 = {
            // Individual bits.
            BIT_0 = 0x1,
            BIT_1 = 0x2,
            BIT_3 = 0x4,
            // Named mask.
            BAR_MASK = 0xf0 => BAR_FIELD,
            // Unnamed mask.
            _ = 0xf00 => BAZ_FIELD,
        });
        #[cfg(feature = "names")]
        struct Constants {
            foo: &'static ConstantNames<u32>,
            bar: &'static FlagNames<u32>,
            quux: &'static ConstantNames<u64>,
        }
        constants! {
            struct Base;
            consts foo: u32 = FOO;
            flags bar: u32 = BAR;
            // Inline constant definitions.
            consts quux: u64 = {
                QUUX_A = 1,
                QUUX_B = 1,
            };
        }
        constants! {
            struct Arch(Base);
            // Does not inherit from Base::foo directly
            // (but the FOO_ARCH definition below does inherit FOO).
            consts foo: u32 = FOO_ARCH;
            // Inherits names from Base::bar.
            flags bar: u32 = {
                BIT_4 = 0x8,
            };
        }
        constant_names!(FOO_ARCH: u32 = FOO + {
            FOO_ARCH_A = 100,
        });

        #[cfg(feature = "names")]
        {
            let constants = Arch::constants();
            assert_eq!(constants.foo.name(FOO_A), Some("FOO_A"));
            assert_eq!(constants.foo.name(FOO_ARCH_A), Some("FOO_ARCH_A"));
            assert_eq!(
                constants.bar.bits_iter().find(|(v, _)| *v == BIT_1),
                Some((BIT_1, "BIT_1")),
            );
            assert_eq!(
                constants.bar.bits_iter().find(|(v, _)| *v == BIT_4),
                Some((BIT_4, "BIT_4")),
            );
            assert_eq!(
                constants
                    .bar
                    .groups_iter()
                    .find_map(|group| group.name(BAR_B)),
                Some("BAR_B"),
            );
            assert_eq!(
                constants
                    .bar
                    .groups_iter()
                    .find_map(|group| group.name(BAR_D)),
                Some("BAR_D"),
            );
            assert_eq!(
                constants
                    .bar
                    .groups_iter()
                    .find_map(|group| group.name(BAZ_B)),
                Some("BAZ_B"),
            );
        }
    }
}
