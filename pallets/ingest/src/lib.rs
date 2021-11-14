//! # Ingest pallet
//! The module for ingesting NFT content for further moderation.
//!
//! ## Overview
//!
//! This module provides basic functions to create and manager
//!

//! ### Module Functions
//!
//! - `ingest` - inputs content in moderation queue.

#![cfg_attr(not(feature = "std"), no_std)]

use log;
use codec::{Decode, Encode};
use scale_info::TypeInfo;

use sp_core::{
	crypto::KeyTypeId,
	offchain::{Duration, OpaqueMultiaddr, Timestamp},
};
use sp_std::{
	str,
	vec::Vec,
	collections::btree_map::BTreeMap,
	fmt::Debug,
};

use frame_support::{
	pallet_prelude::*,
	sp_runtime::traits::Hash,
};
use frame_system::{
	offchain::{
		AppCrypto, CreateSignedTransaction, SendSignedTransaction, SendUnsignedTransaction,
		SignedPayload, Signer, SigningTypes, SubmitTransaction,
	},
	pallet_prelude::*,
};

/// Defines application identifier for crypto keys of this module.
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"jygg");

/// Pallet-specific crypto type wrapper based on `KeyTypeId`.
pub mod crypto {
	use super::KEY_TYPE;
	use sp_core::ed25519::Signature as Ed25519Signature;
	use sp_runtime::{
		app_crypto::{app_crypto, ed25519},
		traits::Verify,
		MultiSignature, MultiSigner,
	};

	app_crypto!(ed25519, KEY_TYPE);

	pub struct AuthId;

	// implemented for ocw-runtime
	impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for AuthId {
		type RuntimeAppPublic = Public;
		type GenericPublic = sp_core::ed25519::Public;
		type GenericSignature = sp_core::ed25519::Signature;
	}
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, scale_info::TypeInfo)]
pub struct Payload<Public> {
	number: u64,
	public: Public,
}

impl<T: SigningTypes> SignedPayload<T> for Payload<T::Public> {
	fn public(&self) -> T::Public {
		self.public.clone()
	}
}

#[derive(Clone, Default, Encode, Decode, PartialEq, RuntimeDebug, TypeInfo)]
pub struct ContentMetadata {
	pub name: Vec<u8>,
	pub content_uri: Vec<u8>,
	pub mime_type: MimeType,
	pub review_context: Option<BTreeMap<Vec<u8>, Vec<u8>>>,
}

#[derive(Clone, Encode, Decode, PartialEq, RuntimeDebug, TypeInfo)]
pub enum MimeType {
	TextPlain,
	ImagePNG,
	AnyAny,
}

impl Default for MimeType {
	fn default() -> Self {
		MimeType::AnyAny
	}
}

#[derive(Clone, Encode, Decode, PartialEq, RuntimeDebug, TypeInfo)]
pub enum Violation {
	DrugUse,
	Nudity,
	CSAM,
	None
}

impl Default for Violation {
	fn default() -> Self {
		Violation::None
	}
}

pub use module::*;

#[frame_support::pallet]
pub mod module {
	use codec::FullCodec;
	use frame_support::StorageHasher;
	use super::*;

	#[pallet::config]
	pub trait Config: frame_system::Config + CreateSignedTransaction<Call<Self>> {
		/// The identifier type for an offchain worker.
		type AuthorityId: AppCrypto<Self::Public, Self::Signature>;
		/// The overarching dispatch call type.
		type Call: From<Call<Self>>;
		/// The overarching event type.
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

		/// The content token ID type.
		type ContentTokenId: Clone + Default + PartialEq + TypeInfo + FullCodec + Debug;
		/// The content metadata type.
		type ContentMetadata: Clone + Default + PartialEq + TypeInfo + FullCodec + Debug;
		/// Violation that caused content rejection.
		type ViolationReason: Clone + Default + PartialEq + TypeInfo + FullCodec + Debug;
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub (super) fn deposit_event)]
	pub enum Event<T: Config> {
		ContentIngested(T::ContentTokenId),
		ContentApproved(T::ContentTokenId),
		ContentRejected(T::ContentTokenId, T::ViolationReason),
	}

	#[pallet::error]
	pub enum Error<T> {}

	#[pallet::pallet]
	#[pallet::generate_store(pub (super) trait Store)]
	pub struct Pallet<T>(_);

	#[derive(Clone, Encode, Decode, PartialEq, RuntimeDebug, TypeInfo)]
	#[scale_info(skip_type_params(T))]
	pub enum ProcessingRequest<T: Config> {
		Auto(T::ContentTokenId),
		HumanRequired(T::ContentTokenId),
	}

	/// ProcessingId defines id of single content item moderation processing,
	/// and is a xxHash64 of (T::ContentTokenId, T::ContentMetadata).
	pub type ProcessingId<T> = <T as frame_system::Config>::Hash;

	pub type ModerationTicket<T: Config> = (T::ContentTokenId, T::ContentMetadata, ProcessingId<T>);

	#[pallet::storage]
	#[pallet::getter(fn assets_by_account)]
	// A list of addresses to connect to and disconnect from.
	pub(super) type ModerationPackages<T: Config> = StorageMap<_, Blake2_128Concat, T::ContentTokenId, ModerationTicket<T>, ValueQuery>;

	#[pallet::storage]
	// A list of addresses to connect to and disconnect from.
	pub(super) type ProcessingQueue<T: Config> = StorageValue<_, Vec<ProcessingRequest<T>>, ValueQuery>;

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// ...
		#[pallet::weight(100_000)]
		pub fn ingest(origin: OriginFor<T>,
					  token_id: T::ContentTokenId,
					  metadata: T::ContentMetadata,
		) -> DispatchResult {
			let _ = ensure_signed(origin)?;

			let processing_id = Encode::using_encoded(
				&(token_id.clone(), &metadata.clone()),
				Twox64Concat::hash);

			<ModerationPackages<T>>::insert(token_id.clone(),
											(token_id.clone(), metadata, processing_id));
			<ProcessingQueue<T>>::mutate(|tickets | {
				tickets.push(ProcessingRequest::Auto(token_id.clone()));
			});

			Self::deposit_event(Event::ContentIngested(token_id));

			Ok(())
		}
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn on_initialize(block_number: T::BlockNumber) -> Weight {
			<ProcessingQueue<T>>::kill();

			0
		}

		fn offchain_worker(block_number: T::BlockNumber) {
			if let Err(e) = Self::process_incoming() {
				log::debug!("Failed processing incoming package: {:?}", e);
			}
		}
	}
}

impl<T: Config> Pallet<T> {
	fn process_incoming() -> Result<(), Error<T>> {
		for request in ProcessingQueue::<T>::get() {
			if let ProcessingRequest::Auto(content_id) = request {
				// TODO: request data from IPFS.
				// Do inference processing here (algorithm or external API).
				// Then try make a decision (approved, rejected, quarantined) with rule-engine (Inc contracts).
			}
		}

		Ok(())
	}
}
