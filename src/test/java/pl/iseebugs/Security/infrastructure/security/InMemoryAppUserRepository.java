package pl.iseebugs.Security.infrastructure.security;

import org.springframework.data.domain.Example;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.repository.query.FluentQuery;
import pl.iseebugs.Security.domain.user.AppUser;
import pl.iseebugs.Security.domain.user.AppUserRepository;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;

public class InMemoryAppUserRepository implements AppUserRepository {
    private final AtomicLong index = new AtomicLong(1);
    private final Map<Long, AppUser> map = new HashMap<>();

    public long count(){
        return map.values().size();
    }

    @Override
    public Optional<AppUser> findByEmail(final String email) {
        return map.values().stream()
                .filter(user -> user.getEmail().equals(email))
                .findFirst();
    }

    @Override
    public AppUser save(final AppUser entity) {
        if (entity.getId() == null || entity.getId() == 0) {
            long id = index.getAndIncrement();
            entity.setId(id);
        }
        try {
            map.put(entity.getId(), entity);
        } catch (Exception e){
            throw new RuntimeException("Failed to save the entity to the database.");
        }
        return entity;
    }

    @Override
    public void enableAppUser(final String email) {

    }

    @Override
    public void deleteByEmail(final String email) {

    }

    @Override
    public void flush() {

    }

    @Override
    public <S extends AppUser> S saveAndFlush(final S entity) {
        return null;
    }

    @Override
    public <S extends AppUser> List<S> saveAllAndFlush(final Iterable<S> entities) {
        return null;
    }

    @Override
    public void deleteAllInBatch(final Iterable<AppUser> entities) {

    }

    @Override
    public void deleteAllByIdInBatch(final Iterable<Long> longs) {

    }

    @Override
    public void deleteAllInBatch() {

    }

    @Override
    public AppUser getOne(final Long aLong) {
        return null;
    }

    @Override
    public AppUser getById(final Long aLong) {
        return null;
    }

    @Override
    public AppUser getReferenceById(final Long aLong) {
        return null;
    }

    @Override
    public <S extends AppUser> Optional<S> findOne(final Example<S> example) {
        return Optional.empty();
    }

    @Override
    public <S extends AppUser> List<S> findAll(final Example<S> example) {
        return null;
    }

    @Override
    public <S extends AppUser> List<S> findAll(final Example<S> example, final Sort sort) {
        return null;
    }

    @Override
    public <S extends AppUser> Page<S> findAll(final Example<S> example, final Pageable pageable) {
        return null;
    }

    @Override
    public <S extends AppUser> long count(final Example<S> example) {
        return 0;
    }

    @Override
    public <S extends AppUser> boolean exists(final Example<S> example) {
        return false;
    }

    @Override
    public <S extends AppUser, R> R findBy(final Example<S> example, final Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) {
        return null;
    }

    @Override
    public <S extends AppUser> List<S> saveAll(final Iterable<S> entities) {
        return null;
    }

    @Override
    public Optional<AppUser> findById(final Long aLong) {
        return Optional.empty();
    }

    @Override
    public boolean existsById(final Long aLong) {
        return false;
    }

    @Override
    public List<AppUser> findAll() {
        return null;
    }

    @Override
    public List<AppUser> findAllById(final Iterable<Long> longs) {
        return null;
    }

    @Override
    public void deleteById(final Long aLong) {

    }

    @Override
    public void delete(final AppUser entity) {

    }

    @Override
    public void deleteAllById(final Iterable<? extends Long> longs) {

    }

    @Override
    public void deleteAll(final Iterable<? extends AppUser> entities) {

    }

    @Override
    public void deleteAll() {

    }

    @Override
    public List<AppUser> findAll(final Sort sort) {
        return null;
    }

    @Override
    public Page<AppUser> findAll(final Pageable pageable) {
        return null;
    }
}
