//
// Copyright 2024 Mochi Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import androidx.benchmark.BenchmarkState;
import androidx.benchmark.junit4.BenchmarkRule;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.mochi.libmochi.protocol.ServiceId;
import org.mochi.libmochi.zkgroup.ServerPublicParams;
import org.mochi.libmochi.zkgroup.ServerSecretParams;
import org.mochi.libmochi.zkgroup.VerificationFailedException;
import org.mochi.libmochi.zkgroup.groups.ClientZkGroupCipher;
import org.mochi.libmochi.zkgroup.groups.GroupSecretParams;
import org.mochi.libmochi.zkgroup.groups.UuidCiphertext;
import org.mochi.libmochi.zkgroup.groupsend.GroupSendDerivedKeyPair;
import org.mochi.libmochi.zkgroup.groupsend.GroupSendEndorsement;
import org.mochi.libmochi.zkgroup.groupsend.GroupSendEndorsementsResponse;

@RunWith(Parameterized.class)
public class GroupSendEndorsements {
  @Rule public final BenchmarkRule benchmarkRule = new BenchmarkRule();

  @Parameters(name = "groupSize={0}")
  public static Object[] data() {
    return new Integer[] {10, 100, 1000};
  }

  private final ServerSecretParams serverParams = ServerSecretParams.generate();
  private final ServerPublicParams serverPublicParams = serverParams.getPublicParams();
  private final GroupSecretParams groupParams = GroupSecretParams.generate();

  private final Instant expiration =
      Instant.now().truncatedTo(ChronoUnit.DAYS).plus(2, ChronoUnit.DAYS);

  private final ServiceId.Aci[] members;
  private final UuidCiphertext[] encryptedMembers;
  private final GroupSendEndorsementsResponse response;

  public GroupSendEndorsements(int groupSize) {
    members = new ServiceId.Aci[groupSize];
    for (int i = 0; i < groupSize; ++i) {
      members[i] = new ServiceId.Aci(UUID.randomUUID());
    }

    encryptedMembers = new UuidCiphertext[groupSize];
    final ClientZkGroupCipher cipher = new ClientZkGroupCipher(groupParams);
    for (int i = 0; i < groupSize; ++i) {
      encryptedMembers[i] = cipher.encrypt(members[i]);
    }

    GroupSendDerivedKeyPair keyPair =
        GroupSendDerivedKeyPair.forExpiration(expiration, serverParams);
    response = GroupSendEndorsementsResponse.issue(Arrays.asList(encryptedMembers), keyPair);
  }

  @Test
  public void benchmarkReceiveWithServiceIds() throws VerificationFailedException {
    final BenchmarkState state = benchmarkRule.getState();

    while (state.keepRunning()) {
      response.receive(Arrays.asList(members), members[0], groupParams, serverPublicParams);
    }
  }

  @Test
  public void benchmarkReceiveWithCiphertexts() throws VerificationFailedException {
    final BenchmarkState state = benchmarkRule.getState();

    while (state.keepRunning()) {
      response.receive(Arrays.asList(encryptedMembers), encryptedMembers[0], serverPublicParams);
    }
  }

  @Test
  public void benchmarkToToken() throws VerificationFailedException {
    final BenchmarkState state = benchmarkRule.getState();
    final List<GroupSendEndorsement> endorsements =
        response
            .receive(Arrays.asList(encryptedMembers), encryptedMembers[0], serverPublicParams)
            .endorsements();

    while (state.keepRunning()) {
      for (GroupSendEndorsement next : endorsements) {
        next.toToken(groupParams);
      }
    }
  }
}
