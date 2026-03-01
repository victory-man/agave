import re

with open("src/shred/merkle.rs", "r") as f:
    content = f.read()

recover_body = """pub(super) fn recover(
    mut shreds: Vec<Shred>,
    reed_solomon_cache: &ReedSolomonCache,
) -> Result<impl Iterator<Item = Result<Shred, Error>>, Error> {
    shreds.sort_unstable_by(cmp_shred_erasure_shard_index);
    let (common_header, coding_header, merkle_root, chained_merkle_root, retransmitter_signature) = {
        let Some(Shred::ShredCode(shred)) = shreds.last() else {
            return Err(Error::from(TooFewParityShards));
        };
        let position = u32::from(shred.coding_header.position);
        let index = shred.common_header.index.checked_sub(position);
        let common_header = ShredCommonHeader {
            index: index.ok_or(Error::from(InvalidIndex))?,
            ..shred.common_header
        };
        let coding_header = CodingShredHeader {
            position: 0u16,
            ..shred.coding_header
        };
        (
            common_header,
            coding_header,
            shred.merkle_root()?,
            shred.chained_merkle_root().ok(),
            shred.retransmitter_signature().ok(),
        )
    };
    debug_assert_matches!(common_header.shred_variant, ShredVariant::MerkleCode { .. });
    let (proof_size, resigned) = match common_header.shred_variant {
        ShredVariant::MerkleCode { proof_size, resigned } => (proof_size, resigned),
        ShredVariant::MerkleData { .. } => return Err(Error::InvalidShredVariant),
    };

    let num_data_shreds = usize::from(coding_header.num_data_shreds);
    let num_coding_shreds = usize::from(coding_header.num_coding_shreds);
    let num_shards = num_data_shreds + num_coding_shreds;

    let mut mask = vec![false; num_shards];
    let mut batch = Vec::with_capacity(num_shards);

    for shred in shreds {
        if shred.signature() != &common_header.signature {
            return Err(Error::InvalidMerkleRoot);
        }
        let erasure_shard_index = shred.erasure_shard_index()?;
        if !(batch.len()..num_shards).contains(&erasure_shard_index) {
            return Err(Error::from(InvalidIndex));
        }
        while batch.len() < erasure_shard_index {
            batch.push(make_stub_shred(
                batch.len(),
                &common_header,
                &coding_header,
                &chained_merkle_root,
                &retransmitter_signature,
            )?);
        }
        mask[erasure_shard_index] = true;
        batch.push(shred);
    }
    while batch.len() < num_shards {
        batch.push(make_stub_shred(
            batch.len(),
            &common_header,
            &coding_header,
            &chained_merkle_root,
            &retransmitter_signature,
        )?);
    }

    let mut shards = batch
        .iter_mut()
        .zip(&mask)
        .map(|(shred, &mask)| Ok((shred.erasure_shard_mut()?, mask)))
        .collect::<Result<Vec<_>, Error>>()?;

    reed_solomon_cache
        .get(num_data_shreds, num_coding_shreds)?
        .reconstruct_data(&mut shards)?;
    drop(shards);

    let nodes = batch
        .iter_mut()
        .zip(&mask)
        .enumerate()
        .map(|(index, (shred, &is_present))| {
            if !is_present && index < num_data_shreds {
                let Shred::ShredData(shred_data) = shred else {
                    return Err(Error::InvalidShredVariant);
                };
                let Ok(common_hdr) =
                    ShredCommonHeader::from_bytes(array_ref![&shred_data.payload[..], 0, 83])
                else {
                    return Err(Error::InvalidShredVariant);
                };
                let Ok(data_hdr) =
                    DataShredHeader::from_bytes(array_ref![&shred_data.payload[..], 83, 5])
                else {
                    return Err(Error::InvalidShredVariant);
                };
                if shred_data.common_header != common_hdr {
                    return Err(Error::InvalidShredVariant);
                }
                shred_data.data_header = data_hdr;
            }
            shred.merkle_node()
        })
        .collect::<Result<Vec<_>, _>>()?;

    let tree = make_merkle_tree(nodes.into_iter().map(Ok))?;
    if tree.last() != Some(&merkle_root) {
        return Err(Error::InvalidMerkleRoot);
    }

    let recovered_data_shreds = batch
        .into_iter()
        .zip(mask)
        .enumerate()
        .filter_map(move |(index, (mut shred, is_present))| {
            if !is_present && index < num_data_shreds {
                let proof = make_merkle_proof(index, num_shards, &tree);
                if let Err(e) = shred.set_merkle_proof(proof) {
                    return Some(Err(e));
                }
                if let Err(e) = shred.sanitize() {
                    return Some(Err(e));
                }
                Some(Ok(shred))
            } else {
                None
            }
        });

    Ok(recovered_data_shreds)
}"""

# Find the start and end of recover function
start_idx = content.find("pub(super) fn recover(")
# Find the end of recover function. It ends right before "// Compares shreds"
end_idx = content.find("// Compares shreds of the same erasure batch", start_idx)

new_content = content[:start_idx] + recover_body + "\n\n" + content[end_idx:]

# Also update the test:
test_old = """            let recovered_shreds: Vec<_> = recover(shreds, reed_solomon_cache)
                .unwrap()
                .map(Result::unwrap)
                .collect();
            assert_eq!(size + recovered_shreds.len(), num_shreds);
            assert_eq!(recovered_shreds.len(), removed_shreds.len());
            removed_shreds.sort_by(|a, b| {
                if a.shred_type() == b.shred_type() {
                    a.index().cmp(&b.index())
                } else if a.shred_type() == ShredType::Data {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            });
            assert_eq!(recovered_shreds, removed_shreds);"""

test_new = """            let recovered_shreds: Vec<_> = recover(shreds, reed_solomon_cache)
                .unwrap()
                .map(Result::unwrap)
                .collect();
            let mut removed_data_shreds: Vec<_> = removed_shreds
                .into_iter()
                .filter(|s| s.shred_type() == ShredType::Data)
                .collect();
            assert_eq!(recovered_shreds.len(), removed_data_shreds.len());
            removed_data_shreds.sort_by(|a, b| a.index().cmp(&b.index()));
            assert_eq!(recovered_shreds, removed_data_shreds);"""

new_content = new_content.replace(test_old, test_new)

with open("src/shred/merkle.rs", "w") as f:
    f.write(new_content)
